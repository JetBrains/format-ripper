using System;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO;

public class MachOSignatureInjector
{
  private const long MaxPaddingBytes = 8;

  struct MachOSectionInfo
  {
    public long SectionOffset;
    public long SectionSize;
    public int Alignment;
  }

  /// <summary>
  /// Inject signature into a Mach-O file
  /// </summary>
  /// <param name="sourceStream">Read-only stream of a file into which you want to inject a signature</param>
  /// <param name="outputStream">Stream for writing a result file with an injected signature</param>
  /// <param name="signatureTransferData">Signature transfer data to inject</param>
  /// <exception cref="ArgumentException">Thrown if output stream is not writeable</exception>
  /// <exception cref="FormatException">Thrown if input file has invalid format</exception>
  /// <exception cref="SignatureInjectionException">Thrown on signature transfer error. This usually happens when trying to transfer signatures between incompatible files.</exception>
  public static unsafe void InjectSignature(Stream sourceStream, Stream outputStream, IMachOSignatureTransferData signatureTransferData)
  {
    if (!outputStream.CanWrite) throw new ArgumentException("Provided stream is not writeable");

    sourceStream.Position = 0;
    uint rawMagic;
    StreamUtil.ReadBytes(sourceStream, (byte*)&rawMagic, sizeof(uint));
    var magic = (MH)MemoryUtil.GetLeU4(rawMagic);

    var isFat = magic is MH.FAT_MAGIC or MH.FAT_CIGAM or MH.FAT_MAGIC_64 or MH.FAT_CIGAM_64;

    if (!isFat)
    {
      if (signatureTransferData.SectionSignatures.Length != 1)
        throw new SignatureInjectionException($"Invalid number of signatures for the non-FAT Mach-O. Expected 1, but got {signatureTransferData.SectionSignatures.Length}");

      TransferSectionSignature(
        sourceStream,
        new StreamRange(0, sourceStream.Length),
        outputStream,
        magic,
        signatureTransferData.SectionSignatures[0]);
    }
    else
    {
      ProcessFatMachO(sourceStream, outputStream, magic, signatureTransferData);
    }
  }

  private static unsafe void ProcessFatMachO(Stream sourceStream, Stream outputStream, MH fatMagic, IMachOSignatureTransferData signatureTransferData)
  {
    var isFatLittleEndian = fatMagic is MH.FAT_MAGIC or MH.FAT_MAGIC_64;
    var needSwap = BitConverter.IsLittleEndian != isFatLittleEndian;

    uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
    ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

    fat_header fh;
    StreamUtil.ReadBytes(sourceStream, (byte*)&fh, sizeof(fat_header));
    var nFatArch = GetU4(fh.nfat_arch);

    if (signatureTransferData.SectionSignatures.Length != nFatArch)
      throw new SignatureInjectionException($"Cannot transfer signatures: source and destination files have different number of sections. The source file has {signatureTransferData.SectionSignatures.Length} section(s) and the destination file has {nFatArch} section(s).");

    uint rawFatMagic = MemoryUtil.GetLeU4((uint)fatMagic);
    StreamUtil.WriteBytes(outputStream, (byte*)&rawFatMagic, sizeof(uint));
    StreamUtil.WriteBytes(outputStream, (byte*)&fh, sizeof(fat_header));

    long fatNodesOffset = sourceStream.Position;

    if (fatMagic is MH.FAT_CIGAM_64 or MH.FAT_MAGIC_64)
    {
      var fatNodes = new fat_arch_64[checked((int)nFatArch)];
      fixed (fat_arch_64* ptr = fatNodes)
      {
        int fatNodesSize = checked((int)nFatArch * sizeof(fat_arch_64));
        StreamUtil.ReadBytes(sourceStream, (byte*)ptr, fatNodesSize);
        StreamUtil.WriteBytes(outputStream, (byte*)ptr, fatNodesSize);

        for (var n = 0; n < nFatArch; n++)
        {
          var processedSection = ProcessSection(
            sourceStream,
            outputStream,
            new MachOSectionInfo()
            {
              SectionOffset = checked((long)GetU8(fatNodes[n].offset)),
              SectionSize = checked((long)GetU8(fatNodes[n].size)),
              Alignment = (int)GetU4(fatNodes[n].align)
            },
            signatureTransferData.SectionSignatures[n]);

          fatNodes[n].offset = GetU8((ulong)processedSection.SectionOffset);
          fatNodes[n].size = GetU8((ulong)processedSection.SectionSize);
        }

        outputStream.Seek(fatNodesOffset, SeekOrigin.Begin);
        StreamUtil.WriteBytes(outputStream, (byte*)ptr, fatNodesSize);
      }
    }
    else
    {
      var fatNodes = new fat_arch[checked((int)nFatArch)];
      fixed (fat_arch* ptr = fatNodes)
      {
        int fatNodesSize = checked((int)nFatArch * sizeof(fat_arch));
        StreamUtil.ReadBytes(sourceStream, (byte*)ptr, fatNodesSize);
        StreamUtil.WriteBytes(outputStream, (byte*)ptr, fatNodesSize);

        for (var n = 0; n < nFatArch; n++)
        {
          var processedSection = ProcessSection(
            sourceStream,
            outputStream,
            new MachOSectionInfo()
            {
              SectionOffset = GetU4(fatNodes[n].offset),
              SectionSize = GetU4(fatNodes[n].size),
              Alignment = (int)GetU4(fatNodes[n].align)
            },
            signatureTransferData.SectionSignatures[n]);

          fatNodes[n].offset = GetU4(checked((uint)processedSection.SectionOffset));
          fatNodes[n].size = GetU4(checked((uint)processedSection.SectionSize));
        }

        // Update fat nodes with new offsets and sizes
        outputStream.Seek(fatNodesOffset, SeekOrigin.Begin);
        StreamUtil.WriteBytes(outputStream, (byte*)ptr, fatNodesSize);
      }
    }
  }

  private static unsafe MachOSectionInfo ProcessSection(Stream sourceStream, Stream outputStream, MachOSectionInfo sectionInfo, IMachOSectionSignatureTransferData? sectionSignature)
  {
    sourceStream.Position = sectionInfo.SectionOffset;
    uint rawSubMagic;
    StreamUtil.ReadBytes(sourceStream, (byte*)&rawSubMagic, sizeof(uint));
    var subMagic = (MH)MemoryUtil.GetLeU4(rawSubMagic);

    WritePaddingBytes(outputStream, sectionInfo.Alignment);

    long sectionStart = outputStream.Position;
    long writtenBytes = TransferSectionSignature(
      sourceStream,
      new StreamRange(sectionInfo.SectionOffset, sectionInfo.SectionSize),
      outputStream,
      subMagic,
      sectionSignature);

    return new MachOSectionInfo()
    {
      SectionOffset = sectionStart,
      SectionSize = writtenBytes,
      Alignment = sectionInfo.Alignment
    };
  }

  private static void WritePaddingBytes(Stream outputStream, int alignment)
  {
    long currentPosition = outputStream.Position;
    long alignmentBytes = 1 << alignment;

    long requiredBytes = (alignmentBytes - currentPosition % alignmentBytes) % alignmentBytes;

    byte[] buffer = new byte[checked((int)requiredBytes)];

    outputStream.Write(buffer, 0, buffer.Length);
  }

  private static unsafe long TransferSectionSignature(Stream sourceStream, StreamRange sourceStreamRange, Stream outputStream, MH magic, IMachOSectionSignatureTransferData? sectionSignature)
  {
    if (sectionSignature == null)
      throw new SignatureInjectionException($"Cannot transfer the signature for section: it is not signed in the original file");

    long outputStreamInitialPosition = outputStream.Position;
    long PositionFromStart() => outputStream.Position - outputStreamInitialPosition;

    var isLittleEndian = magic is MH.MH_MAGIC or MH.MH_MAGIC_64;
    var needSwap = BitConverter.IsLittleEndian != isLittleEndian;

    uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
    ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

    uint rawMagic = MemoryUtil.GetLeU4((uint)magic);
    StreamUtil.WriteBytes(outputStream, (byte*)&rawMagic, sizeof(uint));

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
      throw new FormatException($"Invalid Mach-O magic: {magic.ToString("X")}");
    }

    uint oldSignatureOffset = 0;
    uint commandNumber = 0;
    fixed (byte* buf = StreamUtil.ReadBytes(sourceStream, checked((int)sizeofcmds)))
    {
      for (var cmdPtr = buf; commandNumber++ < ncmds;)
      {
        load_command lc;
        MemoryUtil.CopyBytes(cmdPtr, (byte*)&lc, sizeof(load_command));
        uint cmdSize = GetU4(lc.cmdsize);
        var payloadLcPtr = cmdPtr + sizeof(load_command);
        var commandType = (LC)GetU4(lc.cmd);

        if (commandNumber == sectionSignature.LastLinkeditCommandNumber)
        {
          if (commandType == LC.LC_SEGMENT_64)
          {
            segment_command_64 sc;
            MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command_64));
            sc.vmsize = GetU8(sectionSignature.LastLinkeditVmSize64);
            sc.filesize = GetU8(sectionSignature.LastLinkeditFileSize64);

            MemoryUtil.CopyBytes((byte*)&sc, payloadLcPtr, sizeof(segment_command_64));
          }
          else if (commandType == LC.LC_SEGMENT)
          {
            segment_command sc;
            MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command));
            sc.vmsize = GetU4(sectionSignature.LastLinkeditVmSize32);
            sc.filesize = GetU4(sectionSignature.LastLinkeditFileSize32);

            MemoryUtil.CopyBytes((byte*)&sc, payloadLcPtr, sizeof(segment_command));
          }
          else
          {
            throw new SignatureInjectionException($"Error injecting signature. Load command number {sectionSignature.LastLinkeditCommandNumber} was supposed to be either LC_SEGMENT or LC_SEGMENT_64, but {commandType.ToString()} was found");
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

    long end = oldSignatureOffset != 0 ? sourceStreamRange.Position + oldSignatureOffset : sourceStreamRange.Position + sourceStreamRange.Size;

    StreamUtil.CopyBytes(sourceStream, outputStream, end - sourceStream.Position);

    if (PositionFromStart() < sectionSignature.LinkEditDataOffset)
    {
      long paddingBytes = sectionSignature.LinkEditDataOffset - PositionFromStart();
      if (paddingBytes > MaxPaddingBytes)
        throw new SignatureInjectionException($"Too many padding bytes required between payload and signature. Expected no more than {MaxPaddingBytes} bytes, but required {paddingBytes} bytes. Seems that the donor and the acceptor files are incompatible.");

      byte[] padding = new byte[paddingBytes];
      outputStream.Write(padding, 0, padding.Length);
    }

    if (PositionFromStart() == sectionSignature.LinkEditDataOffset)
    {
      outputStream.Write(sectionSignature.SignatureBlob, 0, sectionSignature.SignatureBlob.Length);
    }
    else
    {
      throw new SignatureInjectionException($"Failed to inject signature due to invalid output stream position. Expected {sectionSignature.LinkEditDataOffset}, got {PositionFromStart()}");
    }

    return PositionFromStart();
  }
}
