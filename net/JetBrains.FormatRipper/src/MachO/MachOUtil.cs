using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO
{
  public static class MachOUtil
  {
    public static bool NeedSwap(MachOFile.Endian endian) => BitConverter.IsLittleEndian != endian switch
      {
        MachOFile.Endian.Little => true,
        MachOFile.Endian.Big => false,
        _ => throw new ArgumentOutOfRangeException(nameof(endian), endian, null)
      };

    public static string ReadStringZ(Stream stream) => StreamUtil.ReadStringZ(stream);

    public sealed class LoadCommandsInfo
    {
      public readonly bool HasSignature;
      public readonly MachOFile.SignatureType SignatureType;
      public readonly SignatureData SignatureData;
      public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
      public readonly IEnumerable<CDHash> CDHashes;
      public readonly IMachOSectionSignatureTransferData? SectionSignatureTransferData;
      public readonly byte[]? Entitlements;
      public readonly byte[]? EntitlementsDer;

      public LoadCommandsInfo(bool hasSignature, MachOFile.SignatureType signatureType, SignatureData signatureData, IEnumerable<HashVerificationUnit> hashVerificationUnits, IEnumerable<CDHash> cdHashes, IMachOSectionSignatureTransferData? sectionSignatureTransferData, byte[]? entitlements, byte[]? entitlementsDer)
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

    public static unsafe LoadCommandsInfo ReadLoadCommands(MachOFile.Section section, MachOFile.Mode mode = MachOFile.Mode.Default)
    {
      var endian = section.Endian;
      var commands = section.Commands;
      var imageOffset = section.ImageOffset;
      var sizeOfCmds = section.SizeOfLoadCommands;

      var needSwap = NeedSwap(endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      var nCmds = (uint)commands.Length;

      var hasSignature = false;
      MachOFile.SignatureType signatureType = MachOFile.SignatureType.None;
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

            if ((mode & MachOFile.Mode.SignatureData) == MachOFile.Mode.SignatureData)
            {
              using var sectionStream = section.CreateStream();
              sectionStream.Position = GetU4(ldc.dataoff);
              sectionSignatureTransferData.SignatureBlob = StreamUtil.ReadBytes(sectionStream, checked((int)GetU4(ldc.datasize)));
              sectionStream.Position = GetU4(ldc.dataoff);

              CS_SuperBlob cssb;
              StreamUtil.ReadBytes(sectionStream, (byte*)&cssb, sizeof(CS_SuperBlob));
              if ((CSMAGIC)EndianUtil.GetBeU4(cssb.magic) != CSMAGIC.CSMAGIC_EMBEDDED_SIGNATURE)
                throw new FormatException("Invalid Mach-O code embedded signature magic");
              var csLength = EndianUtil.GetBeU4(cssb.length);
              if (csLength < sizeof(CS_SuperBlob))
                throw new FormatException("Too small Mach-O code signature super blob");

              var csCount = EndianUtil.GetBeU4(cssb.count);
              fixed (byte* scBuf = StreamUtil.ReadBytes(sectionStream, checked((int)csLength - sizeof(CS_SuperBlob))))
              {
                ComputeHashInfo[] specialSlotPositions = new ComputeHashInfo[(uint)CSSLOT.CSSLOT_HASHABLE_ENTRIES_MAX - 1];

                for (int superBlobEntryIndex = 0; superBlobEntryIndex < csCount; superBlobEntryIndex++)
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

                    specialSlotPositions[(uint)slotType - 1] = new ComputeHashInfo(0,
                      new[]
                        {
                          new StreamRange(checked(imageOffset + GetU4(ldc.dataoff) + offset), EndianUtil.GetBeU4(csb.length))
                        },
                      0);
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
                      if (signatureType == MachOFile.SignatureType.None)
                        signatureType = MachOFile.SignatureType.AdHoc;

                      if (slotType == CSSLOT.CSSLOT_CODEDIRECTORY)
                        codeDirectoryBlob = currentCodeDirectoryBlob;

                      int codeSlots = checked((int)EndianUtil.GetBeU4(cscd.nCodeSlots));
                      int specialSlots = checked((int)EndianUtil.GetBeU4(cscd.nSpecialSlots));
                      uint zeroHashOffset = EndianUtil.GetBeU4(cscd.hashOffset);
                      long codeLimit = EndianUtil.GetBeU4(cscd.codeLimit);
                      int pageSize = cscd.pageSize > 0 ? 1 << cscd.pageSize : 0;
                      string hashName = CS_HASHTYPE.GetHashName(cscd.hashType);

                      var cdHash = new CDHash(hashName,
                        new ComputeHashInfo(0,
                          new[]
                            {
                              new StreamRange(checked(imageOffset + GetU4(ldc.dataoff) + offset), cscdLength)
                            },
                          0));

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

                        var computeHashInfo = new ComputeHashInfo(0,
                          new[]
                            {
                              new StreamRange(pageStart + imageOffset, currentPageSize)
                            },
                          0);

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
                      signatureType = MachOFile.SignatureType.Regular;
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
        (mode & MachOFile.Mode.SignatureData) == MachOFile.Mode.SignatureData && signatureType != MachOFile.SignatureType.None ? sectionSignatureTransferData : null,
        entitlements,
        entitlementsDer);
    }

    public sealed class Symbol
    {
      public readonly string Name;
      public readonly NT Type;
      public readonly byte SectionIndex;
      public readonly ND Description;
      public readonly ulong Value;
      public readonly MachOFile.CreateStreamDelegate? CreateStream;

      internal Symbol(
        string name,
        NT type,
        byte sectionIndex,
        ND description,
        ulong value,
        MachOFile.CreateStreamDelegate? createStream)
      {
        Name = name;
        Type = type;
        SectionIndex = sectionIndex;
        Description = description;
        Value = value;
        CreateStream = createStream;
      }
    }

    public sealed class DataSection
    {
      public readonly string SectionName;
      public readonly string SegmentName;
      public readonly ulong Address;
      public readonly ulong Size;
      public readonly SEC Flags;
      public readonly MachOFile.CreateStreamDelegate? CreateSection;

      internal DataSection(
        string sectionName,
        string segmentName,
        ulong address,
        ulong size,
        SEC flags,
        MachOFile.CreateStreamDelegate? createSection)
      {
        SectionName = sectionName;
        SegmentName = segmentName;
        Address = address;
        Size = size;
        Flags = flags;
        CreateSection = createSection;
      }
    }

    public delegate bool SymbolFilterDelegate(Symbol symbol);

    /// <summary>
    /// Reads the <see cref="LC.LC_SYMTAB"/> symbol table of the Mach-O image. The <paramref name="dataSections"/> are
    /// the ones returned by <see cref="ReadDataSections"/> for the same <paramref name="section"/>. The parsed stream
    /// should stay opened while the <see cref="Symbol.CreateStream"/> delegates are in use.
    /// </summary>
    public static unsafe bool GetSymbols(MachOFile.Section section, List<DataSection> dataSections, SymbolFilterDelegate symbolFilter)
    {
      var needSwap = NeedSwap(section.Endian);
      ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      symtab_command? symtab = null;
      foreach (var command in section.Commands)
        if (command.Type == LC.LC_SYMTAB)
        {
          using var cmdStream = command.CreateStream();
          symtab_command stc;
          StreamUtil.ReadBytes(cmdStream, (byte*)&stc, sizeof(symtab_command));
          if ((LC)GetU4(stc.cmd) != LC.LC_SYMTAB)
            throw new FormatException($"Invalid {nameof(symtab_command)} type");
          if (GetU4(stc.cmdsize) < sizeof(symtab_command))
            throw new FormatException($"Invalid {nameof(symtab_command)} size");
          symtab = stc;
          break;
        }

      if (symtab == null)
        return true;

      var symCount = checked((int)GetU4(symtab.Value.nsyms));
      var strSize = GetU4(symtab.Value.strsize);

      var isAbi64 = (section.CpuType & CPU_TYPE.CPU_ARCH_ABI64) == CPU_TYPE.CPU_ARCH_ABI64;
      var entrySize = isAbi64 ? sizeof(nlist_64) : sizeof(nlist);

      using var sectionStream = section.CreateStream();
      using var strStream = new ReadOnlyNestedStream(sectionStream, GetU4(symtab.Value.stroff), strSize);
      using var symStream = new ReadOnlyNestedStream(sectionStream, GetU4(symtab.Value.symoff), checked((long)symCount * entrySize));

      for (var n = 0; n < symCount; ++n)
      {
        uint nStrX;
        NT nType;
        byte nSect;
        ND nDesc;
        ulong nValue;
        if (isAbi64)
        {
          nlist_64 nl;
          StreamUtil.ReadBytes(symStream, (byte*)&nl, sizeof(nlist_64));
          nStrX = GetU4(nl.n_strx);
          nType = (NT)nl.n_type;
          nSect = nl.n_sect;
          nDesc = (ND)GetU2(nl.n_desc);
          nValue = GetU8(nl.n_value);
        }
        else
        {
          nlist nl;
          StreamUtil.ReadBytes(symStream, (byte*)&nl, sizeof(nlist));
          nStrX = GetU4(nl.n_strx);
          nType = (NT)nl.n_type;
          nSect = nl.n_sect;
          nDesc = (ND)GetU2(nl.n_desc);
          nValue = GetU4(nl.n_value);
        }

        if (nStrX > strSize)
          throw new FormatException("Invalid Mach-O symbol name index");
        strStream.Position = nStrX;
        var str = ReadStringZ(strStream);

        MachOFile.CreateStreamDelegate? createStream = null;
        if ((nType & NT.N_STAB) == 0 && (nType & NT.N_TYPE) == NT.N_SECT)
        {
          if (nSect == 0 || nSect >= dataSections.Count)
            throw new FormatException("Invalid Mach-O symbol section number");

          var data = dataSections[nSect];
          var headerDataSection = dataSections[0];
          if (!IsZeroFill(data.Flags))
            if (nSect == 1 && headerDataSection.Address <= nValue && nValue < headerDataSection.Address + headerDataSection.Size)
              createStream = MakeCreateStream(headerDataSection, nValue);
            else
              createStream = MakeCreateStream(data, nValue);
        }

        if (!symbolFilter(new Symbol(str, nType, nSect, nDesc, nValue, createStream)))
          return false;
      }

      return true;

      static MachOFile.CreateStreamDelegate MakeCreateStream(DataSection data, ulong nValue)
      {
        var offset = checked((long)(nValue - data.Address));
        var size = checked((long)(data.Address + data.Size - nValue));
        return () => new ReadOnlyNestedStream(data.CreateSection!(), offset, size);
      }
    }

    /// <summary>
    /// Reads the data sections of the Mach-O image. The declared sections are placed at their <c>n_sect</c> numbers, so
    /// the returned list starts with the recreated hidden __TEXT,__mach_header section. The mach header with the load commands
    /// is placed by the linker into the hidden __TEXT,__mach_header section, which is never emitted into the section table.
    /// The __mh_execute_header symbol still refers to it through n_sect==1, so the section is recreated here.
    /// </summary>
    public static unsafe List<DataSection> ReadDataSections(MachOFile.Section machOSection)
    {
      var needSwap = NeedSwap(machOSection.Endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      var headerSize = (ulong)(sizeof(uint) /* magic */ + ((machOSection.CpuType & CPU_TYPE.CPU_ARCH_ABI64) == CPU_TYPE.CPU_ARCH_ABI64
        ? sizeof(mach_header_64)
        : sizeof(mach_header))) + machOSection.SizeOfLoadCommands;

      DataSection? headerDataSection = null;
      var dataSections = new List<DataSection>();
      foreach (var command in machOSection.Commands)
        switch (command.Type)
        {
        case LC.LC_SEGMENT:
          {
            using var cmdStream = command.CreateStream();
            segment_command sc;
            StreamUtil.ReadBytes(cmdStream, (byte*)&sc, sizeof(segment_command));
            if ((LC)GetU4(sc.cmd) != LC.LC_SEGMENT)
              throw new FormatException($"Invalid {nameof(segment_command)} type");
            var nSects = GetU4(sc.nsects);
            if (GetU4(sc.cmdsize) < checked(sizeof(segment_command) + nSects * sizeof(section)))
              throw new FormatException($"Invalid {nameof(segment_command)} size");
            headerDataSection ??= MakeHeaderDataSection(
              machOSection,
              GetName(sc.segname, 16),
              GetU4(sc.vmaddr),
              GetU4(sc.fileoff),
              GetU4(sc.filesize),
              headerSize);
            for (var n = 0u; n < nSects; ++n)
            {
              section sec;
              StreamUtil.ReadBytes(cmdStream, (byte*)&sec, sizeof(section));
              dataSections.Add(MakeDataSection(
                machOSection,
                GetName(sec.sectname, 16),
                GetName(sec.segname, 16),
                GetU4(sec.addr),
                GetU4(sec.size),
                GetU4(sec.offset),
                (SEC)GetU4(sec.flags)));
            }
          }
          break;
        case LC.LC_SEGMENT_64:
          {
            using var cmdStream = command.CreateStream();
            segment_command_64 sc;
            StreamUtil.ReadBytes(cmdStream, (byte*)&sc, sizeof(segment_command_64));
            if ((LC)GetU4(sc.cmd) != LC.LC_SEGMENT_64)
              throw new FormatException($"Invalid {nameof(segment_command_64)} type");
            var nSects = GetU4(sc.nsects);
            if (GetU4(sc.cmdsize) < checked(sizeof(segment_command_64) + nSects * sizeof(section_64)))
              throw new FormatException($"Invalid {nameof(segment_command_64)} size");
            headerDataSection ??= MakeHeaderDataSection(
              machOSection,
              GetName(sc.segname, 16),
              GetU8(sc.vmaddr),
              GetU8(sc.fileoff),
              GetU8(sc.filesize),
              headerSize);
            for (var n = 0u; n < nSects; ++n)
            {
              section_64 sec;
              StreamUtil.ReadBytes(cmdStream, (byte*)&sec, sizeof(section_64));
              dataSections.Add(MakeDataSection(
                machOSection,
                GetName(sec.sectname, 16),
                GetName(sec.segname, 16),
                GetU8(sec.addr),
                GetU8(sec.size),
                GetU4(sec.offset),
                (SEC)GetU4(sec.flags)));
            }
          }
          break;
        }

      if (headerDataSection == null)
        throw new FormatException("Missing the Mach-O header data section");
      dataSections.Insert(0, headerDataSection);
      return dataSections;

      static DataSection? MakeHeaderDataSection(MachOFile.Section machOSection, string segmentName, ulong address, ulong fileOffset, ulong fileSize, ulong headerSize)
      {
        if (fileOffset == 0 && fileSize >= headerSize)
          return MakeDataSection(machOSection, "__mach_header", segmentName, address, headerSize, 0, SEC.S_REGULAR);
        return null;
      }

      static DataSection MakeDataSection(MachOFile.Section machOSection, string sectionName, string segmentName, ulong address, ulong size, ulong fileOffset, SEC flags)
      {
        return new DataSection(sectionName, segmentName, address, size, flags, !IsZeroFill(flags)
          ? new MachOFile.CreateStreamDelegate(() => new ReadOnlyNestedStream(machOSection.CreateStream(), checked((long)fileOffset), checked((long)size)))
          : null);
      }

      static string GetName(byte* buf, int nameSize)
      {
        var blob = MemoryUtil.CopyBytes(buf, nameSize);
        return new string(Encoding.UTF8.GetChars(blob, 0, MemoryUtil.GetAsciiStringZSize(blob)));
      }
    }

    public static bool IsZeroFill(SEC flags) => (flags & SEC.SECTION_TYPE) is SEC.S_ZEROFILL or SEC.S_GB_ZEROFILL or SEC.S_THREAD_LOCAL_ZEROFILL;

    public static IMachOSignatureTransferData? ReadSignatureTransferData(MachOFile machOFile, MachOFile.Mode mode = MachOFile.Mode.SignatureData)
    {
      var sections = machOFile.Sections;
      var sectionSignatures = new IMachOSectionSignatureTransferData?[sections.Length];

      var hasSignature = false;
      for (var i = 0; i < sections.Length; i++)
      {
        var loadCommandsInfo = ReadLoadCommands(sections[i], mode);
        hasSignature |= loadCommandsInfo.HasSignature;
        sectionSignatures[i] = loadCommandsInfo.SectionSignatureTransferData;
      }

      return hasSignature ? new MachOSignatureTransferData(sectionSignatures) : null;
    }
  }
}
