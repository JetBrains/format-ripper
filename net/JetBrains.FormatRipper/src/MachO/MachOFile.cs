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
      public readonly bool HasSignature;
      public readonly SignatureData SignatureData;
      public readonly ComputeHashInfo? ComputeHashInfo;

      internal Section(
        bool isLittleEndian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        bool hasSignature,
        SignatureData signatureData,
        ComputeHashInfo? computeHashInfo)
      {
        IsLittleEndian = isLittleEndian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        HasSignature = hasSignature;
        SignatureData = signatureData;
        ComputeHashInfo = computeHashInfo;
      }
    }

    public readonly bool? IsFatLittleEndian;
    public readonly Section[] Sections;

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1,
      ComputeHashInfo = 0x2
    }

    private MachOFile(bool? isFatLittleEndian, Section[] sections)
    {
      IsFatLittleEndian = isFatLittleEndian;
      Sections = sections;
    }

    public static unsafe bool Is(Stream stream)
    {
      static bool Check(MH magic) => magic is MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64;

      stream.Position = 0;
      uint rawMagic;
      StreamUtil.ReadBytes(stream, (byte*)&rawMagic, sizeof(uint));
      var magic = (MH)MemoryUtil.GetLeU4(rawMagic);

      if (magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 or MH.FAT_CIGAM or MH.FAT_CIGAM_64)
      {
        var isFatLittleEndian = magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64;
        var needSwap = BitConverter.IsLittleEndian != isFatLittleEndian;

        uint GetU4(uint v) => needSwap ? MemoryUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        if (magic is MH.FAT_CIGAM_64 or MH.FAT_MAGIC_64)
        {
          var fatNodes = new fat_arch_64[checked((int)nFatArch)];
          fixed (fat_arch_64* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch_64)));
          for (var n = 0; n < nFatArch; n++)
          {
            stream.Position = checked((long)GetU8(fatNodes[n].offset));
            uint rawSubMagic;
            StreamUtil.ReadBytes(stream, (byte*)&rawSubMagic, sizeof(uint));
            var subMagic = (MH)MemoryUtil.GetLeU4(rawSubMagic);

            if (!Check(subMagic))
              return false;
          }
        }
        else
        {
          var fatNodes = new fat_arch[checked((int)nFatArch)];
          fixed (fat_arch* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch)));
          for (var n = 0; n < nFatArch; n++)
          {
            stream.Position = GetU4(fatNodes[n].offset);
            uint rawSubMagic;
            StreamUtil.ReadBytes(stream, (byte*)&rawSubMagic, sizeof(uint));
            var subMagic = (MH)MemoryUtil.GetLeU4(rawSubMagic);

            if (!Check(subMagic))
              return false;
          }
        }

        return true;
      }

      return Check(magic);
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
          var hasSignature = false;
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
                if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                {
                  segment_command sc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command));
                  var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                  var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                  if (segName == SEG.SEG_LINKEDIT)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(uint)));
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(uint)));
                  }
                }
                break;
              case LC.LC_SEGMENT_64:
                if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                {
                  segment_command_64 sc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command_64));
                  var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                  var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                  if (segName == SEG.SEG_LINKEDIT)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(ulong)));
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(ulong)));
                  }
                }
                break;
              case LC.LC_CODE_SIGNATURE:
                {
                  linkedit_data_command ldc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&ldc, sizeof(linkedit_data_command));
                  if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (cmdPtr - buf)), GetU4(lc.cmdsize)));
                    excludeRanges.Add(new StreamRange(GetU4(ldc.dataoff), GetU4(ldc.datasize)));
                  }

                  if ((mode & Mode.SignatureData) == Mode.SignatureData)
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
                hasSignature = true;
                break;
              }

              cmdPtr += GetU4(lc.cmdsize);
            }

            if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
              if (!hasSignature)
                excludeRanges.Add(new StreamRange(checked(cmdOffset + sizeOfCmds), sizeof(load_command) + sizeof(linkedit_data_command)));
          }

          return new(hasSignature, new SignatureData(codeDirectoryBlob, cmsSignatureBlob));
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
          if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
          {
            excludeRanges.Add(new StreamRange(checked(sizeof(MH) + ((byte*)&mh.ncmds - (byte*)&mh)), sizeof(uint)));
            excludeRanges.Add(new StreamRange(checked(sizeof(MH) + ((byte*)&mh.sizeofcmds - (byte*)&mh)), sizeof(uint)));
          }

          var loadCommands = ReadLoadCommands(sizeof(MH) + sizeof(mach_header_64), GetU4(mh.ncmds), GetU4(mh.sizeofcmds));

          ComputeHashInfo? computeHashInfo = null;
          if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
          {
            StreamRangeUtil.Sort(excludeRanges);
            var sortedHashIncludeRanges = StreamRangeUtil.Invert(imageRange.Size, excludeRanges);
            StreamRangeUtil.MergeNeighbors(sortedHashIncludeRanges);
            computeHashInfo = new ComputeHashInfo(imageRange.Position, sortedHashIncludeRanges, GetZeroPadding(loadCommands.HasSignature));
          }

          return new Section(
            isLittleEndian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            loadCommands.HasSignature,
            loadCommands.SignatureData,
            computeHashInfo);
        }
        else
        {
          mach_header mh;
          StreamUtil.ReadBytes(stream, (byte*)&mh, sizeof(mach_header));
          if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
          {
            excludeRanges.Add(new StreamRange(checked(sizeof(MH) + ((byte*)&mh.ncmds - (byte*)&mh)), sizeof(uint)));
            excludeRanges.Add(new StreamRange(checked(sizeof(MH) + ((byte*)&mh.sizeofcmds - (byte*)&mh)), sizeof(uint)));
          }

          var loadCommands = ReadLoadCommands(sizeof(MH) + sizeof(mach_header), GetU4(mh.ncmds), GetU4(mh.sizeofcmds));

          ComputeHashInfo? computeHashInfo = null;
          if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
          {
            StreamRangeUtil.Sort(excludeRanges);
            var sortedHashIncludeRanges = StreamRangeUtil.Invert(imageRange.Size, excludeRanges);
            StreamRangeUtil.MergeNeighbors(sortedHashIncludeRanges);
            computeHashInfo = new ComputeHashInfo(imageRange.Position, sortedHashIncludeRanges, GetZeroPadding(loadCommands.HasSignature));
          }

          return new Section(
            isLittleEndian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            loadCommands.HasSignature,
            loadCommands.SignatureData,
            computeHashInfo);
        }
      }

      stream.Position = 0;
      uint rawMagic;
      StreamUtil.ReadBytes(stream, (byte*)&rawMagic, sizeof(uint));
      var magic = (MH)MemoryUtil.GetLeU4(rawMagic);

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
            var position = checked((long)GetU8(fatNodes[n].offset));
            stream.Position = position;
            uint rawSubMagic;
            StreamUtil.ReadBytes(stream, (byte*)&rawSubMagic, sizeof(uint));
            var subMagic = (MH)MemoryUtil.GetLeU4(rawSubMagic);

            sections[n] = Read(new StreamRange(position, checked((long)GetU8(fatNodes[n].size))), subMagic);
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
            var position = GetU4(fatNodes[n].offset);
            stream.Position = position;
            uint rawSubMagic;
            StreamUtil.ReadBytes(stream, (byte*)&rawSubMagic, sizeof(uint));
            var subMagic = (MH)MemoryUtil.GetLeU4(rawSubMagic);

            sections[n] = Read(new StreamRange(position, GetU4(fatNodes[n].size)), subMagic);
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
      public readonly bool HasSignature;
      public readonly SignatureData SignatureData;

      public LoadCommandsInfo(bool hasSignature, SignatureData signatureData)
      {
        HasSignature = hasSignature;
        SignatureData = signatureData;
      }
    }
  }
}