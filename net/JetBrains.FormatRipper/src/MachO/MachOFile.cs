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
      public readonly SignatureType SignatureType;
      public readonly SignatureData SignatureData;
      public readonly ComputeHashInfo? ComputeHashInfo;
      public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
      public readonly IEnumerable<CDHash> CDHashes;
      public readonly MachOSectionSignatureTransferData? SignatureTransferData;
      public readonly byte[]? Entitlements;
      public readonly byte[]? EntitlementsDer;

      internal Section(
        bool isLittleEndian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        bool hasSignature,
        SignatureType signatureType,
        SignatureData signatureData,
        ComputeHashInfo? computeHashInfo,
        IEnumerable<HashVerificationUnit> hashVerificationUnits,
        IEnumerable<CDHash> cdHashes,
        MachOSectionSignatureTransferData? signatureTransferData,
        byte[]? entitlements,
        byte[]? entitlementsDer)
      {
        IsLittleEndian = isLittleEndian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        HasSignature = hasSignature;
        SignatureType = signatureType;
        SignatureData = signatureData;
        ComputeHashInfo = computeHashInfo;
        HashVerificationUnits = hashVerificationUnits;
        CDHashes = cdHashes;
        SignatureTransferData = signatureTransferData;
        Entitlements = entitlements;
        EntitlementsDer = entitlementsDer;
      }
    }

    public readonly bool? IsFatLittleEndian;
    public readonly Section[] Sections;
    public readonly MachOSignatureTransferData? Signature;

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1,
      ComputeHashInfo = 0x2
    }

    public enum SignatureType
    {
      None,
      AdHoc,
      Regular,
    }

    private MachOFile(bool? isFatLittleEndian, Section[] sections)
    {
      IsFatLittleEndian = isFatLittleEndian;
      Sections = sections;
      Signature = new MachOSignatureTransferData(new MachOSectionSignatureTransferData[sections.Length]);

      for (int i = 0; i < sections.Length; i++)
        Signature.SectionSignatures[i] = sections[i].SignatureTransferData;
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
        ulong GetU8(ulong v) => needSwap ? MemoryUtil.SwapU8(v) : v;

        var excludeRanges = new List<StreamRange>();

        LoadCommandsInfo ReadLoadCommands(long cmdOffset, uint nCmds, uint sizeOfCmds)
        {
          var hasSignature = false;
          SignatureType signatureType = SignatureType.None;
          byte[]? codeDirectoryBlob = null;
          byte[]? cmsSignatureBlob = null;
          byte[]? entitlements = null;
          byte[]? entitlementsDer = null;
          List<HashVerificationUnit> hashVerificationUnits = new List<HashVerificationUnit>();
          List<CDHash> cdHashes = new List<CDHash>();
          uint commandNumber = 0;
          var sectionSignatureTransferData = new MachOSectionSignatureTransferData()
          {
            NumberOfLoadCommands = nCmds,
            SizeOfLoadCommands = sizeOfCmds,
          };

          fixed (byte* buf = StreamUtil.ReadBytes(stream, checked((int)sizeOfCmds)))
          {
            for (var cmdPtr = buf; commandNumber++ < nCmds;)
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

                  sectionSignatureTransferData.LastLinkeditCommandNumber = commandNumber;
                  sectionSignatureTransferData.LastLinkeditVmSize32 = GetU4(sc.vmsize);
                  sectionSignatureTransferData.LastLinkeditFileSize32 = GetU4(sc.filesize);

                  if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                  {
                    var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                    var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                    if (segName == SEG.SEG_LINKEDIT)
                    {
                      excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(uint)));
                      excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(uint)));
                    }
                  }

                  break;
                }
                case LC.LC_SEGMENT_64:
                {
                  segment_command_64 sc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&sc, sizeof(segment_command_64));

                  sectionSignatureTransferData.LastLinkeditCommandNumber = commandNumber;
                  sectionSignatureTransferData.LastLinkeditVmSize64 = GetU8(sc.vmsize);
                  sectionSignatureTransferData.LastLinkeditFileSize64 = GetU8(sc.filesize);

                  if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                  {
                    var segNameBuf = MemoryUtil.CopyBytes(sc.segname, 16);
                    var segName = new string(Encoding.UTF8.GetChars(segNameBuf, 0, MemoryUtil.GetAsciiStringZSize(segNameBuf)));
                    if (segName == SEG.SEG_LINKEDIT)
                    {
                      excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.vmsize - (byte*)&sc)), sizeof(ulong)));
                      excludeRanges.Add(new StreamRange(checked(cmdOffset + (payloadLcPtr - buf) + ((byte*)&sc.filesize - (byte*)&sc)), sizeof(ulong)));
                    }
                  }
                  break;
                }
                case LC.LC_CODE_SIGNATURE:
                {
                  linkedit_data_command ldc;
                  MemoryUtil.CopyBytes(payloadLcPtr, (byte*)&ldc, sizeof(linkedit_data_command));
                  if ((mode & Mode.ComputeHashInfo) == Mode.ComputeHashInfo)
                  {
                    excludeRanges.Add(new StreamRange(checked(cmdOffset + (cmdPtr - buf)), GetU4(lc.cmdsize)));
                    excludeRanges.Add(new StreamRange(GetU4(ldc.dataoff), GetU4(ldc.datasize)));
                  }

                  sectionSignatureTransferData.LcCodeSignatureSize = GetU4(lc.cmdsize);
                  sectionSignatureTransferData.LinkEditDataOffset = GetU4(ldc.dataoff);
                  sectionSignatureTransferData.LinkEditDataSize = GetU4(ldc.datasize);

                  if ((mode & Mode.SignatureData) == Mode.SignatureData)
                  {
                    stream.Position = checked(imageRange.Position + GetU4(ldc.dataoff));
                    sectionSignatureTransferData.SignatureBlob = StreamUtil.ReadBytes(stream, checked((int)GetU4(ldc.datasize)));
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
                      ComputeHashInfo[] specialSlotPositions = new ComputeHashInfo[CSSLOT.CSSLOT_HASHABLE_ENTRIES_MAX - 1];

                      for(int superBlobEntryIndex = 0; superBlobEntryIndex < csCount; superBlobEntryIndex++)
                      {
                        var scPtr = scBuf + superBlobEntryIndex * sizeof(CS_BlobIndex);
                        CS_BlobIndex csbi;
                        MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                        uint slotType = MemoryUtil.GetBeU4(csbi.type);

                        if (slotType >= CSSLOT.CSSLOT_INFOSLOT && slotType <= CSSLOT.CSSLOT_LIBRARY_CONSTRAINT)
                        {
                          uint offset = MemoryUtil.GetBeU4(csbi.offset);
                          var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);

                          CS_Blob csb;
                          MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

                          specialSlotPositions[slotType - 1] = new ComputeHashInfo(0, new[]
                          {
                            new StreamRange(checked(imageRange.Position + GetU4(ldc.dataoff) + offset), MemoryUtil.GetBeU4(csb.length))
                          }, 0);
                        }
                      }

                      for (var scPtr = scBuf; csCount-- > 0; scPtr += sizeof(CS_BlobIndex))
                      {
                        CS_BlobIndex csbi;
                        MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                        uint offset = MemoryUtil.GetBeU4(csbi.offset);
                        var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);
                        uint slotType = MemoryUtil.GetBeU4(csbi.type);
                        switch (slotType)
                        {
                          case CSSLOT.CSSLOT_CODEDIRECTORY:
                          case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES:
                          case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES1:
                          case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES2:
                          case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES3:
                          case CSSLOT.CSSLOT_ALTERNATE_CODEDIRECTORIES4:
                          {
                            CS_CodeDirectory cscd;
                            MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));
                            if ((CSMAGIC)MemoryUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                              throw new FormatException("Invalid Mach-O code directory signature magic");
                            var cscdLength = MemoryUtil.GetBeU4(cscd.length);

                            byte[] currentCodeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
                            if (signatureType == SignatureType.None)
                              signatureType = SignatureType.AdHoc;

                            if (slotType == CSSLOT.CSSLOT_CODEDIRECTORY)
                              codeDirectoryBlob = currentCodeDirectoryBlob;

                            int codeSlots = checked((int)MemoryUtil.GetBeU4(cscd.nCodeSlots));
                            int specialSlots = checked((int)MemoryUtil.GetBeU4(cscd.nSpecialSlots));
                            uint zeroHashOffset = MemoryUtil.GetBeU4(cscd.hashOffset);
                            long codeLimit = MemoryUtil.GetBeU4(cscd.codeLimit);
                            int pageSize = cscd.pageSize > 0 ? 1 << cscd.pageSize : 0;
                            string hashName = CS_HASHTYPE.GetHashName(cscd.hashType);

                            var cdHash = new CDHash(hashName, new ComputeHashInfo(0, new[]
                            {
                              new StreamRange(checked(imageRange.Position + GetU4(ldc.dataoff) + offset), cscdLength)
                            }, 0));

                            cdHashes.Add(cdHash);

                            for (int i = 0; i < codeSlots; i++)
                            {
                              byte[] hash = new byte[cscd.hashSize];
                              Array.Copy(currentCodeDirectoryBlob, checked((int)zeroHashOffset + i * cscd.hashSize), hash, 0, cscd.hashSize);

                              long pageStart = i * pageSize;
                              long currentPageSize;
                              if (pageSize > 0)
                                currentPageSize = pageStart + pageSize > codeLimit ? codeLimit - pageStart : pageSize;
                              else
                                currentPageSize = codeLimit - pageStart;

                              var computeHashInfo = new ComputeHashInfo(0, new[]
                              {
                                new StreamRange(pageStart + imageRange.Position, currentPageSize)
                              }, 0);

                              hashVerificationUnits.Add(new HashVerificationUnit(hashName, hash, computeHashInfo));
                            }

                            for (uint i = 1; i <= specialSlots; i++)
                            {
                              byte[] hash = new byte[cscd.hashSize];
                              Array.Copy(currentCodeDirectoryBlob, checked((int)(zeroHashOffset - i * cscd.hashSize)), hash, 0, cscd.hashSize);

                              if (specialSlotPositions[i - 1] != null)
                                hashVerificationUnits.Add(new HashVerificationUnit(hashName, hash, specialSlotPositions[i - 1]));
                            }
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
                            signatureType = SignatureType.Regular;
                          }
                          break;
                          case CSSLOT.CSSLOT_ENTITLEMENTS:
                          {
                            CS_Entitlements csent;
                            MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csent, sizeof(CS_Entitlements));

                            CSMAGIC entitlementsMagic = (CSMAGIC)MemoryUtil.GetBeU4(csent.magic);
                            if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS)
                              throw new FormatException($"Invalid Mach-O entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                            uint csentLength = MemoryUtil.GetBeU4(csent.length);
                            entitlements = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Entitlements), checked((int)csentLength - sizeof(CS_Entitlements)));
                          }
                          break;
                          case CSSLOT.CSSLOT_ENTITLEMENTS_DER:
                          {
                            CS_Entitlements csent;
                            MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csent, sizeof(CS_Entitlements));

                            CSMAGIC entitlementsMagic = (CSMAGIC)MemoryUtil.GetBeU4(csent.magic);
                            if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER)
                              throw new FormatException($"Invalid Mach-O der-encoded entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                            uint csentLength = MemoryUtil.GetBeU4(csent.length);
                            entitlementsDer = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Entitlements), checked((int)csentLength - sizeof(CS_Entitlements)));
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

          return new(
            hasSignature,
            signatureType,
            new SignatureData(codeDirectoryBlob, cmsSignatureBlob),
            hashVerificationUnits,
            cdHashes,
            (mode & Mode.SignatureData) == Mode.SignatureData && signatureType != SignatureType.None ? sectionSignatureTransferData : null,
            entitlements,
            entitlementsDer);
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
            loadCommands.SignatureType,
            loadCommands.SignatureData,
            computeHashInfo,
            loadCommands.HashVerificationUnits,
            loadCommands.CDHashes,
            loadCommands.SectionSignatureTransferData,
            loadCommands.Entitlements,
            loadCommands.EntitlementsDer);
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
            loadCommands.SignatureType,
            loadCommands.SignatureData,
            computeHashInfo,
            loadCommands.HashVerificationUnits,
            loadCommands.CDHashes,
            loadCommands.SectionSignatureTransferData,
            loadCommands.Entitlements,
            loadCommands.EntitlementsDer);
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
      public readonly SignatureType SignatureType;
      public readonly SignatureData SignatureData;
      public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
      public readonly IEnumerable<CDHash> CDHashes;
      public readonly MachOSectionSignatureTransferData? SectionSignatureTransferData;
      public readonly byte[]? Entitlements;
      public readonly byte[]? EntitlementsDer;

      public LoadCommandsInfo(bool hasSignature, SignatureType signatureType, SignatureData signatureData, IEnumerable<HashVerificationUnit> hashVerificationUnits, IEnumerable<CDHash> cdHashes, MachOSectionSignatureTransferData? sectionSignatureTransferData, byte[]? entitlements, byte[]? entitlementsDer)
      {
        HasSignature = hasSignature;
        SignatureType = signatureType;
        SignatureData = signatureData;
        HashVerificationUnits = hashVerificationUnits;
        CDHashes = cdHashes;
        SectionSignatureTransferData = sectionSignatureTransferData;
        Entitlements = entitlements;
        EntitlementsDer = entitlementsDer;
      }
    }
  }
}