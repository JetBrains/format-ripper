using System;
using System.Collections.Generic;
using System.IO;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO
{
  public sealed class MachOFile
  {
    public delegate Stream CreateStreamDelegate();

    public sealed class Command
    {
      public readonly LC Type;
      public readonly uint Size;
      public readonly CreateStreamDelegate CreateStream;

      internal Command(LC type, uint size, CreateStreamDelegate createStream)
      {
        Type = type;
        Size = size;
        CreateStream = createStream;
      }
    }

    public sealed class Section
    {
      public readonly Endian Endian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly Command[] Commands;
      public readonly bool HasSignature;
      public readonly SignatureType SignatureType;
      public readonly SignatureData SignatureData;
      public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
      public readonly IEnumerable<CDHash> CDHashes;
      public readonly IMachOSectionSignatureTransferData? SignatureTransferData;
      public readonly byte[]? Entitlements;
      public readonly byte[]? EntitlementsDer;

      internal Section(
        Endian endian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        Command[] commands,
        bool hasSignature,
        SignatureType signatureType,
        SignatureData signatureData,
        IEnumerable<HashVerificationUnit> hashVerificationUnits,
        IEnumerable<CDHash> cdHashes,
        IMachOSectionSignatureTransferData? signatureTransferData,
        byte[]? entitlements,
        byte[]? entitlementsDer)
      {
        Endian = endian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        Commands = commands;
        HasSignature = hasSignature;
        SignatureType = signatureType;
        SignatureData = signatureData;
        HashVerificationUnits = hashVerificationUnits;
        CDHashes = cdHashes;
        SignatureTransferData = signatureTransferData;
        Entitlements = entitlements;
        EntitlementsDer = entitlementsDer;
      }
    }

    public readonly Endian? FatEndian;
    public readonly Section[] Sections;
    public readonly IMachOSignatureTransferData? Signature;

    public enum Endian
    {
      Big,
      Little
    }

    [Flags]
    public enum Mode : uint
    {
      Default = 0x0,
      SignatureData = 0x1
    }

    public enum SignatureType
    {
      None,
      AdHoc,
      Regular,
    }

    private MachOFile(Endian? fatEndian, Section[] sections)
    {
      FatEndian = fatEndian;
      Sections = sections;

      var signatureTransferData = new MachOSignatureTransferData(new IMachOSectionSignatureTransferData[sections.Length]);

      bool hasSignature = false;
      for (int i = 0; i < sections.Length; i++)
      {
        hasSignature |= sections[i].HasSignature;
        signatureTransferData.SectionSignatures[i] = sections[i].SignatureTransferData;
      }

      Signature = hasSignature ? signatureTransferData : null;
    }

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = 0;
      var magic = ReadMagic(stream);
      if (magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 or MH.FAT_CIGAM or MH.FAT_CIGAM_64)
      {
        var fatEndian = magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 ? Endian.Little : Endian.Big;

        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        if (magic is MH.FAT_CIGAM_64 or MH.FAT_MAGIC_64)
        {
          var fatNodes = new fat_arch_64[checked((int)nFatArch)];
          fixed (fat_arch_64* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch_64)));
          for (var n = 0; n < nFatArch; ++n)
          {
            ref var fatNode = ref fatNodes[n];
            var offset = GetU8(fatNode.offset);
            var size = GetU8(fatNode.size);

            using var sectionStream = new ReadOnlyNestedStream(stream, checked((long)offset), checked((long)size));
            var sectionMagic = ReadMagic(sectionStream);
            if (sectionMagic is not (MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64))
              return false;
          }
        }
        else
        {
          var fatNodes = new fat_arch[checked((int)nFatArch)];
          fixed (fat_arch* ptr = fatNodes)
            StreamUtil.ReadBytes(stream, (byte*)ptr, checked((int)nFatArch * sizeof(fat_arch)));
          for (var n = 0; n < nFatArch; ++n)
          {
            ref var fatNode = ref fatNodes[n];
            var offset = GetU4(fatNode.offset);
            var size = GetU4(fatNode.size);

            using var sectionStream = new ReadOnlyNestedStream(stream, offset, size);
            var sectionMagic = ReadMagic(sectionStream);
            if (sectionMagic is not (MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64))
              return false;
          }
        }

        return true;
      }

      return magic is MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64;
    }

    public static unsafe MachOFile Parse(Stream stream, Mode mode = Mode.Default)
    {
      Section Read(MH magic, StreamRange imageRange, Stream sectionStream)
      {
        if (magic is not (MH.MH_MAGIC or MH.MH_MAGIC_64 or MH.MH_CIGAM or MH.MH_CIGAM_64))
          throw new FormatException("Unknown Mach-O magic numbers");
        var endian = magic is MH.MH_MAGIC or MH.MH_MAGIC_64 ? Endian.Little : Endian.Big;

        var needSwap = MachOUtil.NeedSwap(endian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        Command[] ReadCommands(uint nCmds, Stream commandStream)
        {
          var commands = new Command[checked((int)nCmds)];
          for (var n = 0; n < commands.Length; ++n)
          {
            var offset = commandStream.Position;

            load_command lc;
            StreamUtil.ReadBytes(commandStream, (byte*)&lc, sizeof(load_command));
            var cmd = (LC)GetU4(lc.cmd);
            var cmdSize = GetU4(lc.cmdsize);
            if (cmdSize < sizeof(load_command))
              throw new FormatException($"Invalid {nameof(load_command)} size");

            commands[n] = new Command(cmd, cmdSize, () => new ReadOnlyNestedStream(commandStream, offset, cmdSize));
            commandStream.Position = offset + cmdSize;
          }

          return commands;
        }

        LoadCommandsInfo ReadLoadCommands(Command[] commands, uint sizeOfCmds)
        {
          var nCmds = (uint)commands.Length;

          var hasSignature = false;
          SignatureType signatureType = SignatureType.None;
          byte[]? codeDirectoryBlob = null;
          byte[]? cmsSignatureBlob = null;
          byte[]? entitlements = null;
          byte[]? entitlementsDer = null;
          List<HashVerificationUnit> hashVerificationUnits = new List<HashVerificationUnit>();
          List<CDHash> cdHashes = new List<CDHash>();
          var sectionSignatureTransferData = new MachOSectionSignatureTransferData()
          {
            NumberOfLoadCommands = nCmds,
            SizeOfLoadCommands = sizeOfCmds,
          };

          for (var n = 0u; n < nCmds; ++n)
          {
            var command = commands[n];
            switch (command.Type)
            {
            case LC.LC_SEGMENT:
              using (var cmdStream = command.CreateStream())
              {
                segment_command sc;
                StreamUtil.ReadBytes(cmdStream, (byte*)&sc, sizeof(segment_command));
                if ((LC)GetU4(sc.cmd) != LC.LC_SEGMENT)
                  throw new FormatException($"Invalid {nameof(segment_command)} type");
                if (GetU4(sc.cmdsize) < sizeof(segment_command))
                  throw new FormatException($"Invalid {nameof(segment_command)} size");

                sectionSignatureTransferData.LastLinkeditCommandNumber = n + 1;
                sectionSignatureTransferData.LastLinkeditVmSize32 = GetU4(sc.vmsize);
                sectionSignatureTransferData.LastLinkeditFileSize32 = GetU4(sc.filesize);
                break;
              }
            case LC.LC_SEGMENT_64:
              using (var cmdStream = command.CreateStream())
              {
                segment_command_64 sc;
                StreamUtil.ReadBytes(cmdStream, (byte*)&sc, sizeof(segment_command_64));
                if ((LC)GetU4(sc.cmd) != LC.LC_SEGMENT_64)
                  throw new FormatException($"Invalid {nameof(segment_command_64)} type");
                if (GetU4(sc.cmdsize) < sizeof(segment_command_64))
                  throw new FormatException($"Invalid {nameof(segment_command_64)} size");

                sectionSignatureTransferData.LastLinkeditCommandNumber = n + 1;
                sectionSignatureTransferData.LastLinkeditVmSize64 = GetU8(sc.vmsize);
                sectionSignatureTransferData.LastLinkeditFileSize64 = GetU8(sc.filesize);
                break;
              }
            case LC.LC_CODE_SIGNATURE:
              using (var cmdStream = command.CreateStream())
              {
                linkedit_data_command ldc;
                StreamUtil.ReadBytes(cmdStream, (byte*)&ldc, sizeof(linkedit_data_command));
                if ((LC)GetU4(ldc.cmd) != LC.LC_CODE_SIGNATURE)
                  throw new FormatException($"Invalid {nameof(linkedit_data_command)} type");
                if (GetU4(ldc.cmdsize) < sizeof(linkedit_data_command))
                  throw new FormatException($"Invalid {nameof(linkedit_data_command)} size");

                sectionSignatureTransferData.LcCodeSignatureSize = GetU4(ldc.cmdsize);
                sectionSignatureTransferData.LinkEditDataOffset = GetU4(ldc.dataoff);
                sectionSignatureTransferData.LinkEditDataSize = GetU4(ldc.datasize);

                if ((mode & Mode.SignatureData) == Mode.SignatureData)
                {
                  stream.Position = checked(imageRange.Position + GetU4(ldc.dataoff));
                  sectionSignatureTransferData.SignatureBlob = StreamUtil.ReadBytes(stream, checked((int)GetU4(ldc.datasize)));
                  stream.Position = checked(imageRange.Position + GetU4(ldc.dataoff));

                  CS_SuperBlob cssb;
                  StreamUtil.ReadBytes(stream, (byte*)&cssb, sizeof(CS_SuperBlob));
                  if ((CSMAGIC)EndianUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
                    throw new FormatException("Invalid Mach-O code embedded signature magic");
                  var csLength = EndianUtil.GetBeU4(cssb.length);
                  if (csLength < sizeof(CS_SuperBlob))
                    throw new FormatException("Too small Mach-O code signature super blob");

                  var csCount = EndianUtil.GetBeU4(cssb.count);
                  fixed (byte* scBuf = StreamUtil.ReadBytes(stream, checked((int)csLength - sizeof(CS_SuperBlob))))
                  {
                    ComputeHashInfo[] specialSlotPositions = new ComputeHashInfo[(uint)CSSLOT.CSSLOT_HASHABLE_ENTRIES_MAX - 1];

                    for(int superBlobEntryIndex = 0; superBlobEntryIndex < csCount; superBlobEntryIndex++)
                    {
                      var scPtr = scBuf + superBlobEntryIndex * sizeof(CS_BlobIndex);
                      CS_BlobIndex csbi;
                      MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                      var slotType = (CSSLOT)EndianUtil.GetBeU4(csbi.type);

                      if (slotType >= CSSLOT.CSSLOT_INFOSLOT && slotType <= CSSLOT.CSSLOT_LIBRARY_CONSTRAINT)
                      {
                        uint offset = EndianUtil.GetBeU4(csbi.offset);
                        var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);

                        CS_Blob csb;
                        MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));

                        specialSlotPositions[(uint)slotType - 1] = new ComputeHashInfo(0, new[]
                          {
                            new StreamRange(checked(imageRange.Position + GetU4(ldc.dataoff) + offset), EndianUtil.GetBeU4(csb.length))
                          }, 0);
                      }
                    }

                    for (var scPtr = scBuf; csCount-- > 0; scPtr += sizeof(CS_BlobIndex))
                    {
                      CS_BlobIndex csbi;
                      MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                      uint offset = EndianUtil.GetBeU4(csbi.offset);
                      var csOffsetPtr = scBuf + offset - sizeof(CS_SuperBlob);
                      var slotType = (CSSLOT)EndianUtil.GetBeU4(csbi.type);
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
                          if ((CSMAGIC)EndianUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                            throw new FormatException("Invalid Mach-O code directory signature magic");
                          var cscdLength = EndianUtil.GetBeU4(cscd.length);

                          byte[] currentCodeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, checked((int)cscdLength));
                          if (signatureType == SignatureType.None)
                            signatureType = SignatureType.AdHoc;

                          if (slotType == CSSLOT.CSSLOT_CODEDIRECTORY)
                            codeDirectoryBlob = currentCodeDirectoryBlob;

                          int codeSlots = checked((int)EndianUtil.GetBeU4(cscd.nCodeSlots));
                          int specialSlots = checked((int)EndianUtil.GetBeU4(cscd.nSpecialSlots));
                          uint zeroHashOffset = EndianUtil.GetBeU4(cscd.hashOffset);
                          long codeLimit = EndianUtil.GetBeU4(cscd.codeLimit);
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
                          if ((CSMAGIC)EndianUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
                            throw new FormatException("Invalid Mach-O blob wrapper signature magic");
                          var csbLength = EndianUtil.GetBeU4(csb.length);
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

                          CSMAGIC entitlementsMagic = (CSMAGIC)EndianUtil.GetBeU4(csent.magic);
                          if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS)
                            throw new FormatException($"Invalid Mach-O entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                          uint csentLength = EndianUtil.GetBeU4(csent.length);
                          entitlements = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Entitlements), checked((int)csentLength - sizeof(CS_Entitlements)));
                        }
                        break;
                      case CSSLOT.CSSLOT_ENTITLEMENTS_DER:
                        {
                          CS_Entitlements csent;
                          MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csent, sizeof(CS_Entitlements));

                          CSMAGIC entitlementsMagic = (CSMAGIC)EndianUtil.GetBeU4(csent.magic);
                          if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER)
                            throw new FormatException($"Invalid Mach-O der-encoded entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                          uint csentLength = EndianUtil.GetBeU4(csent.length);
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

        if (magic is MH.MH_MAGIC_64 or MH.MH_CIGAM_64)
        {
          mach_header_64 mh;
          StreamUtil.ReadBytes(stream, (byte*)&mh, sizeof(mach_header_64));
          var nCmds = GetU4(mh.ncmds);
          var sizeOfCmds = GetU4(mh.sizeofcmds);

          var offset = stream.Position;

          Command[] commands;
          using (var commandsStream = new ReadOnlyNestedStream(stream, offset, sizeOfCmds))
            commands = ReadCommands(nCmds, commandsStream);

          stream.Position = offset;
          var loadCommands = ReadLoadCommands(commands, sizeOfCmds);

          return new Section(
            endian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            commands,
            loadCommands.HasSignature,
            loadCommands.SignatureType,
            loadCommands.SignatureData,
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
          var nCmds = GetU4(mh.ncmds);
          var sizeOfCmds = GetU4(mh.sizeofcmds);

          var offset = stream.Position;

          Command[] commands;
          using (var commandsStream = new ReadOnlyNestedStream(stream, offset, sizeOfCmds))
            commands = ReadCommands(nCmds, commandsStream);

          stream.Position = offset;
          var loadCommands = ReadLoadCommands(commands, sizeOfCmds);

          return new Section(
            endian,
            (CPU_TYPE)GetU4(mh.cputype),
            (CPU_SUBTYPE)GetU4(mh.cpusubtype),
            (MH_FileType)GetU4(mh.filetype),
            (MH_Flags)GetU4(mh.flags),
            commands,
            loadCommands.HasSignature,
            loadCommands.SignatureType,
            loadCommands.SignatureData,
            loadCommands.HashVerificationUnits,
            loadCommands.CDHashes,
            loadCommands.SectionSignatureTransferData,
            loadCommands.Entitlements,
            loadCommands.EntitlementsDer);
        }
      }

      stream.Position = 0;
      var magic = ReadMagic(stream);
      if (magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 or MH.FAT_CIGAM or MH.FAT_CIGAM_64)
      {
        var fatEndian = magic is MH.FAT_MAGIC or MH.FAT_MAGIC_64 ? Endian.Little : Endian.Big;

        var needSwap = MachOUtil.NeedSwap(fatEndian);
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        fat_header fh;
        StreamUtil.ReadBytes(stream, (byte*)&fh, sizeof(fat_header));
        var nFatArch = GetU4(fh.nfat_arch);

        var sections = new Section[nFatArch];
        if (magic is MH.FAT_CIGAM_64 or MH.FAT_MAGIC_64)
        {
          using var fatStream = new ReadOnlyNestedStream(stream, stream.Position, checked((int)nFatArch * sizeof(fat_arch_64)));
          for (var n = 0u; n < nFatArch; ++n)
          {
            fat_arch_64 fa;
            StreamUtil.ReadBytes(fatStream, (byte*)&fa, sizeof(fat_arch_64));
            var cpuType = (CPU_TYPE)GetU4(fa.cputype);
            var cpuSubType = (CPU_SUBTYPE)GetU4(fa.cpusubtype);
            var offset = GetU8(fa.offset);
            var size = GetU8(fa.size);

            using var sectionStream = new ReadOnlyNestedStream(stream, checked((long)offset), checked((long)size));
            var sectionMagic = ReadMagic(sectionStream);
            var section = Read(sectionMagic, new StreamRange(checked((long)offset), checked((long)size)), sectionStream);
            if (section.CpuType != cpuType)
              throw new FormatException("Inconsistent cpu type in fat header");
            if (section.CpuSubType != cpuSubType)
              throw new FormatException("Inconsistent cpu subtype in fat header");
            sections[n] = section;
          }
        }
        else
        {
          using var fatStream = new ReadOnlyNestedStream(stream, stream.Position, checked((int)nFatArch * sizeof(fat_arch)));
          for (var n = 0u; n < nFatArch; ++n)
          {
            fat_arch fa;
            StreamUtil.ReadBytes(fatStream, (byte*)&fa, sizeof(fat_arch));
            var cpuType = (CPU_TYPE)GetU4(fa.cputype);
            var cpuSubType = (CPU_SUBTYPE)GetU4(fa.cpusubtype);
            var offset = GetU4(fa.offset);
            var size = GetU4(fa.size);

            using var sectionStream = new ReadOnlyNestedStream(stream, offset, size);
            var sectionMagic = ReadMagic(sectionStream);
            var section = Read(sectionMagic, new StreamRange(offset, size), sectionStream);
            if (section.CpuType != cpuType)
              throw new FormatException("Inconsistent cpu type in fat header");
            if (section.CpuSubType != cpuSubType)
              throw new FormatException("Inconsistent cpu subtype in fat header");
            sections[n] = section;
          }
        }

        return new(fatEndian, sections);
      }

      return new(null, new[] { Read(magic, new StreamRange(0, stream.Length), stream) });
    }

    private static unsafe MH ReadMagic(Stream stream)
    {
      uint rawMagic;
      StreamUtil.ReadBytes(stream, (byte*)&rawMagic, sizeof(uint));
      return (MH)EndianUtil.GetLeU4(rawMagic);
    }

    private sealed class LoadCommandsInfo
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