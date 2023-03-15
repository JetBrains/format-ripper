using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO
{
  public sealed class MachOFile
  {
    public sealed class Section
    {
      public readonly bool IsLittleEndian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly bool HasCodeSignature;
      public readonly byte[]? CodeDirectoryBlob;
      public readonly byte[]? CmsSignatureBlob;
      public readonly ComputeHashInfo ComputeHashInfo;

      internal Section(
        bool isLittleEndian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        bool hasCodeSignature,
        byte[]? codeDirectoryBlob,
        byte[]? cmsSignatureBlob,
        ComputeHashInfo computeHashInfo)
      {
        IsLittleEndian = isLittleEndian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        HasCodeSignature = hasCodeSignature;
        CodeDirectoryBlob = codeDirectoryBlob;
        CmsSignatureBlob = cmsSignatureBlob;
        ComputeHashInfo = computeHashInfo;
      }
    }

    public readonly bool? IsFatLittleEndian;
    public readonly Section[] Sections;

    [Flags]
    public enum Mode : uint
    {
      Default = 0,
      ReadCodeSignature = 0x1
    }

    private MachOFile(bool? isFatLittleEndian, Section[] sections)
    {
      IsFatLittleEndian = isFatLittleEndian;
      Sections = sections;
    }

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = 0;
      MH magic;
      StreamUtil.ReadBytes(stream, (byte*)&magic, sizeof(MH));
      return magic is
        MH.FAT_MAGIC or MH.FAT_MAGIC_64 or MH.FAT_CIGAM or MH.FAT_CIGAM_64 or
        MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64;
    }

    public static unsafe MachOFile Parse(Stream stream, Mode mode = Mode.Default)
    {
      Section Read(StreamRange imageRange, MH magic)
      {
        if (magic is not (MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64))
          throw new FormatException("Unknown Mach-O magic numbers");

        var isLittleEndian = magic is MH.MH_MAGIC or MH.MH_MAGIC_64;
        var needSwap = BitConverter.IsLittleEndian != isLittleEndian;

        uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;

        var excludeRanges = new List<StreamRange>();

        LoadCommandsInfo ReadLoadCommands(long cmdOffset, uint nCmds, uint sizeOfCmds)
        {
          var hasCodeSignature = false;
          byte[]? codeDirectoryBlob = null;
          byte[]? cmsSignatureBlob = null;
          fixed (byte* buf = StreamUtil.ReadBytes(stream, checked((int)sizeOfCmds)))
          {
            for (var cmdPtr = buf; nCmds-- > 0;)
            {
              load_command lc;
              MemoryUtil.CopyBytes(cmdPtr, (byte*)&lc, sizeof(load_command));
              var payloadLcPtr = cmdPtr + sizeof(load_command);

              switch ((LC)GetU4(lc.cmd))
              {
              case LC.LC_SEGMENT:
                {
                  segment_command sc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command));
                  var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                  var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                  if (segName == SEG.SEG_LINKEDIT)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(UInt32)));
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(UInt32)));
                  }
                }
                break;
              case LC.LC_SEGMENT_64:
                {
                  segment_command_64 sc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command_64));
                  var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                  var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                  if (segName == SEG.SEG_LINKEDIT)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(UInt64)));
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(UInt64)));
                  }
                }
                break;
              case LC.LC_CODE_SIGNATURE:
                {
                  linkedit_data_command ldc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&ldc, sizeof(linkedit_data_command));
                  excludeRanges.Add(new StreamRange(checked(cmdOffset + (cmdPtr - buf)), lc.cmdsize));
                  excludeRanges.Add(new StreamRange(ldc.dataoff, ldc.datasize));

                  if ((mode & Mode.ReadCodeSignature) == Mode.ReadCodeSignature)
                  {
                    stream.Position = checked(imageRange.Position + GetU4(ldc.dataoff));

                    CS_SuperBlob cssb;
                    StreamUtil.ReadBytes(stream, (byte*)&cssb, sizeof(CS_SuperBlob));
                    if ((CSMAGIC)MemoryUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
                      throw new FormatException("Invalid Mach-O code embedded signature magic");
                    var csLength = MemoryUtil.GetBeU4(cssb.length);
                    if (csLength < sizeof(CS_SuperBlob))
                      throw new FormatException("Too small Mach-O code signature super blob");

                    var csCount = MemoryUtil.GetBeU4(cssb.count);
                    fixed (byte* scBuf = StreamUtil.ReadBytes(stream, checked((int)csLength - sizeof(CS_SuperBlob))))
                    {
                      for (var scPtr = scBuf; csCount-- > 0; scPtr += sizeof(CS_BlobIndex))
                      {
                        CS_BlobIndex csbi;
                        MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                        var csOffsetPtr = scBuf + MemoryUtil.GetBeU4(csbi.offset) - sizeof(CS_SuperBlob);
                        switch (MemoryUtil.GetBeU4(csbi.type))
                        {
                        case CSSLOT.CSSLOT_CODEDIRECTORY:
                          {
                            CS_CodeDirectory cscd;
                            MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));
                            if ((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                              throw new FormatException("Invalid Mach-O code directory signature magic");
                            var cscdLength = MemoryUtil.GetBeU4(cscd.length);
                            codeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
                          }
                          break;
                        case CSSLOT.CSSLOT_CMS_SIGNATURE:
                          {
                            CS_Blob csb;
                            MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));
                            if ((CSMAGIC)MemoryUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
                              throw new FormatException("Invalid Mach-O blob wrapper signature magic");
                            var csbLength = MemoryUtil.GetBeU4(csb.length);
                            if (csbLength < sizeof(CS_Blob))
                              throw new FormatException("Too small Mach-O cms signature blob length");
                            cmsSignatureBlob = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob), checked((int)csbLength - sizeof(CS_Blob)));
                          }
                          break;
                        }
                      }
                    }
                  }
                }
                hasCodeSignature = true;
                break;
              }

              cmdPtr += GetU4(lc.cmdsize);
            }
            if (!hasCodeSignature)
              excludeRanges.Add(new StreamRange(checked(cmdOffset + sizeOfCmds), sizeof(load_command) + sizeof(linkedit_data_command)));
          }

          return new(hasCodeSignature, codeDirectoryBlob, cmsSignatureBlob);
        }

        int GetZeroPadding(bool hasCodeSignature)
        {
          if (hasCodeSignature)
            return 0;
          var count = (int)(imageRange.Size % 16);
          return count == 0 ? 0 : 16 - count;
        }

        if (magic is MH.MH_MAGIC_64 or MH.MH_CIGAM_64)
        {
          mach_header_64 mh;
          StreamUtil.ReadBytes(stream, (byte*)&mh, sizeof(mach_header_64));
          excludeRanges.Add(new StreamRange(checked(sizeof(MH) + (byte*)&mh.ncmds - (byte*)&mh), sizeof(UInt32)));
          excludeRanges.Add(new StreamRange(checked(sizeof(MH) + (byte*)&mh.sizeofcmds - (byte*)&mh), sizeof(UInt32)));

          var loadCommands = ReadLoadCommands(sizeof(MH) + sizeof(mach_header_64), GetU4(mh.ncmds), GetU4(mh.sizeofcmds));
          StreamRangeUtil.Sort(excludeRanges);
          var sortedHashIncludeRanges = StreamRangeUtil.Invert(imageRange.Size, excludeRanges);
          StreamRangeUtil.MergeNeighbors(sortedHashIncludeRanges);

          return new Section(
            isLittleEndian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            loadCommands.HasCodeSignature,
            loadCommands.CodeDirectoryBlob,
            loadCommands.CmsSignatureBlob,
            new ComputeHashInfo(imageRange.Position, sortedHashIncludeRanges, GetZeroPadding(loadCommands.HasCodeSignature)));
        }
        else
        {
          mach_header mh;
          StreamUtil.ReadBytes(stream, (byte*)&mh, sizeof(mach_header));
          excludeRanges.Add(new StreamRange(checked(sizeof(MH) + (byte*)&mh.ncmds - (byte*)&mh), sizeof(UInt32)));
          excludeRanges.Add(new StreamRange(checked(sizeof(MH) + (byte*)&mh.sizeofcmds - (byte*)&mh), sizeof(UInt32)));

          var loadCommands = ReadLoadCommands(sizeof(MH) + sizeof(mach_header), GetU4(mh.ncmds), GetU4(mh.sizeofcmds));
          StreamRangeUtil.Sort(excludeRanges);
          var sortedHashIncludeRanges = StreamRangeUtil.Invert(imageRange.Size, excludeRanges);
          StreamRangeUtil.MergeNeighbors(sortedHashIncludeRanges);

          return new Section(
            isLittleEndian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            loadCommands.HasCodeSignature,
            loadCommands.CodeDirectoryBlob,
            loadCommands.CmsSignatureBlob,
            new ComputeHashInfo(imageRange.Position, sortedHashIncludeRanges, GetZeroPadding(loadCommands.HasCodeSignature)));
        }
      }

      stream.Position = 0;
      MH magic;
      StreamUtil.ReadBytes(stream, (byte*)&magic, sizeof(MH));

      if (magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 or MH.FAT_CIGAM or MH.FAT_CIGAM_64)
      {
        var isFatLittleEndian = magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64;
        var needSwap = BitConverter.IsLittleEndian != isFatLittleEndian;

        uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);
        var sections = new Section[nFatArch];

        if (magic is MH.FAT_CIGAM_64 or MH.FAT_MAGIC_64)
        {
          var fatNodes = new fat_arch_64[checked((int)nFatArch)];
          fixed (fat_arch_64* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch_64)));
          for (var n = 0; n < nFatArch; n++)
          {
            var imageRange = new StreamRange(checked((long)GetU8(fatNodes[n].offset)), checked((long)GetU8(fatNodes[n].size)));
            stream.Position = imageRange.Position;
            MH subMagic;
            StreamUtil.ReadBytes(stream, (byte*)&subMagic, sizeof(MH));
            sections[n] = Read(imageRange, subMagic);
            if (sections[n].CpuType != (CPU_TYPE)GetU4(fatNodes[n].cputype))
              throw new FormatException("Inconsistent cpu type in fat header");
            if (sections[n].CpuSubType != (CPU_SUBTYPE)GetU4(fatNodes[n].cpusubtype))
              throw new FormatException("Inconsistent cpu subtype in fat header");
          }
        }
        else
        {
          var fatNodes = new fat_arch[checked((int)nFatArch)];
          fixed (fat_arch* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch)));
          for (var n = 0; n < nFatArch; n++)
          {
            var imageRange = new StreamRange(GetU4(fatNodes[n].offset), GetU4(fatNodes[n].size));
            stream.Position = imageRange.Position;
            MH subMagic;
            StreamUtil.ReadBytes(stream, (byte*)&subMagic, sizeof(MH));
            sections[n] = Read(imageRange, subMagic);
            if (sections[n].CpuType != (CPU_TYPE)GetU4(fatNodes[n].cputype))
              throw new FormatException("Inconsistent cpu type in fat header");
            if (sections[n].CpuSubType != (CPU_SUBTYPE)GetU4(fatNodes[n].cpusubtype))
              throw new FormatException("Inconsistent cpu subtype in fat header");
          }
        }

        return new(isFatLittleEndian, sections);
      }

      return new(null, new[] { Read(new StreamRange(0, stream.Length), magic) });
    }

    private readonly struct LoadCommandsInfo
    {
      public readonly bool HasCodeSignature;
      public readonly byte[]? CodeDirectoryBlob;
      public readonly byte[]? CmsSignatureBlob;

      public LoadCommandsInfo(bool hasCodeSignature, byte[]? codeDirectoryBlob, byte[]? cmsSignatureBlob)
      {
        HasCodeSignature = hasCodeSignature;
        CodeDirectoryBlob = codeDirectoryBlob;
        CmsSignatureBlob = cmsSignatureBlob;
      }
    }
  }
}