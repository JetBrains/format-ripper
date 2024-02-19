using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO;

public class MachOSignatureInjector
{
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, MachOFileSignature signature)
  {
    if (!outputStream.CanWrite) throw new ArgumentException("Provided stream is not writeable");

    // var macho = MachOFile.Parse(sourceStream, MachOFile.Mode.SignatureData);
    //
    // if (macho.Sections.Length != signature.SectionSignatures.Length)
    //   throw new SignatureInjectionException($"Number of sections in target file ({macho.Sections.Length} sections) doesn't match the number of section signatures provided ({signature.SectionSignatures.Length} signatures)");

    // for (int i = 0; i < macho.Sections.Length; i++)
    // {
    //   InjectInSection(sourceStream, macho.Sections[i], signature.SectionSignatures[i]);
    // }

    sourceStream.Position = 0;
    uint rawMagic;
    StreamUtil.ReadBytes(sourceStream, (byte*)&rawMagic, sizeof(uint));
    var magic = (MH)MemoryUtil.GetLeU4(rawMagic);

    StreamUtil.WriteBytes(outputStream, (byte*)&rawMagic, sizeof(uint));

    var isLittleEndian = magic is MH.MH_MAGIC or MH.MH_MAGIC_64;
    var needSwap = BitConverter.IsLittleEndian != isLittleEndian;

    uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
    ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

    MachOSectionSignature sectionSignature = signature.SectionSignatures[0];

    uint ncmds;
    uint sizeofcmds;
    bool signatureLoadCommandMissing = false;

    if (magic is MH.MH_MAGIC_64 or MH.MH_CIGAM_64)
    {
      mach_header_64 mh;
      StreamUtil.ReadBytes(sourceStream, (byte*)&mh, sizeof(mach_header_64));

      ncmds = GetU4(mh.ncmds);
      sizeofcmds = GetU4(mh.sizeofcmds);

      if (ncmds == sectionSignature.NumberOfLoadCommands - 1)
      {
        mh.ncmds = GetU4(sectionSignature.NumberOfLoadCommands);
        mh.sizeofcmds = GetU4(sectionSignature.SizeOfLoadCommands);
        signatureLoadCommandMissing = true;
      }
      else if (ncmds != sectionSignature.NumberOfLoadCommands)
      {
        throw new SignatureInjectionException($"Target file has wrong number of load commands. Expected {sectionSignature.NumberOfLoadCommands} or {sectionSignature.NumberOfLoadCommands - 1}, but found {ncmds}");
      }

      StreamUtil.WriteBytes(outputStream, (byte*)&mh, sizeof(mach_header_64));
    }
    else if (magic is MH.MH_MAGIC or MH.MH_CIGAM)
    {
      mach_header mh;
      StreamUtil.ReadBytes(sourceStream, (byte*)&mh, sizeof(mach_header));

      ncmds = GetU4(mh.ncmds);
      sizeofcmds = GetU4(mh.sizeofcmds);

      if (ncmds == sectionSignature.NumberOfLoadCommands - 1)
      {
        mh.ncmds = GetU4(sectionSignature.NumberOfLoadCommands);
        mh.sizeofcmds = GetU4(sectionSignature.SizeOfLoadCommands);
        signatureLoadCommandMissing = true;
      }
      else if (ncmds != sectionSignature.NumberOfLoadCommands)
      {
        throw new SignatureInjectionException($"Target file has wrong number of load commands. Expected {sectionSignature.NumberOfLoadCommands} or {sectionSignature.NumberOfLoadCommands - 1}, but found {ncmds}");
      }

      StreamUtil.WriteBytes(outputStream, (byte*)&mh, sizeof(mach_header));
    }
    else
    {
      throw new SignatureInjectionException($"Unsupported Mach-O magic {magic.ToString("X2")}");
    }

    long position = sourceStream.Position;
    uint oldSignatureOffset = 0;
    uint commandNumber = 0;
    fixed (byte* buf = StreamUtil.ReadBytes(sourceStream, checked((int)sizeofcmds)))
    {
      for (var cmdPtr = buf; commandNumber++ < ncmds;)
      {
        load_command lc;
        MemoryUtil.CopyBytes(cmdPtr, (byte*)&lc, sizeof(load_command));
        uint cmdSize = GetU4(lc.cmdsize);

        position += sizeof(load_command);

        var payloadLcPtr = cmdPtr + sizeof(load_command);
        var commandType = (LC)GetU4(lc.cmd);

        if (commandNumber == sectionSignature.LastLinkeditCommandNumber)
        {
          if (commandType == LC.LC_SEGMENT_64)
          {
            segment_command_64 sc;
            MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command_64));
            var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
            var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
            sc.vmsize = GetU8(sectionSignature.LastLinkeditVmSize64);
            sc.filesize = GetU8(sectionSignature.LastLinkeditFileSize64);

            MemoryUtil.CopyBytes((byte*)&sc, payloadLcPtr, sizeof(segment_command_64));
          }
          else if (commandType == LC.LC_SEGMENT)
          {
            segment_command sc;
            MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command));
            var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
            var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
            sc.vmsize = GetU4(sectionSignature.LastLinkeditVmSize32);
            sc.filesize = GetU4(sectionSignature.LastLinkeditFileSize32);

            MemoryUtil.CopyBytes((byte*)&sc, payloadLcPtr, sizeof(segment_command));
          }
        }

        if (commandType == LC.LC_CODE_SIGNATURE)
        {
          linkedit_data_command ldc;
          MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&ldc, sizeof(linkedit_data_command));

          oldSignatureOffset = GetU4(ldc.dataoff);

          ldc.dataoff = GetU4(sectionSignature.LinkEditDataOffset);
          ldc.datasize = GetU4(sectionSignature.LinkEditDataSize);

          MemoryUtil.CopyBytes((byte*)&ldc, payloadLcPtr, sizeof(linkedit_data_command));
        }

        cmdPtr += cmdSize;
        position += cmdSize;
      }

      StreamUtil.WriteBytes(outputStream, buf, checked((int)sizeofcmds));
    }


    if (signatureLoadCommandMissing)
    {
      load_command signatureLc = new load_command()
      {
        cmd = GetU4((uint)LC.LC_CODE_SIGNATURE),
        cmdsize = GetU4(sectionSignature.LcCodeSignatureSize),
      };

      StreamUtil.WriteBytes(outputStream, (byte*)&signatureLc, sizeof(load_command));

      linkedit_data_command signatureLdc = new linkedit_data_command()
      {
        dataoff = GetU4(sectionSignature.LinkEditDataOffset),
        datasize = GetU4(sectionSignature.LinkEditDataSize),
      };

      StreamUtil.WriteBytes(outputStream, (byte*)&signatureLdc, sizeof(linkedit_data_command));

      sourceStream.Seek(sizeof(load_command) + sizeof(linkedit_data_command), SeekOrigin.Current);
    }


    long end = oldSignatureOffset != 0 ? oldSignatureOffset : sourceStream.Length;

    long remainingBytes = end - sourceStream.Position;

    long maxChunk = 1024 * 1024;

    byte[] buffer = new byte[maxChunk];

    while (remainingBytes > 0)
    {
      long chunk = Math.Min(maxChunk, remainingBytes);

      int actualRead = sourceStream.Read(buffer, 0, (int)chunk);

      outputStream.Write(buffer, 0, actualRead);

      remainingBytes -= actualRead;
    }

    if (outputStream.Position < sectionSignature.LinkEditDataOffset)
    {
      byte[] padding = new byte[sectionSignature.LinkEditDataOffset - outputStream.Length];
      outputStream.Write(padding, 0, padding.Length);
    }

    if (outputStream.Position == sectionSignature.LinkEditDataOffset)
    {
      outputStream.Write(sectionSignature.SignatureBlob, 0, sectionSignature.SignatureBlob.Length);
    }

  }
}