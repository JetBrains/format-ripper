using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
      public readonly MachOUtil.SignatureType SignatureType;
      public readonly SignatureData SignatureData;
      public readonly IEnumerable<HashVerificationUnit> HashVerificationUnits;
      public readonly IEnumerable<CDHash> CDHashes;
      public readonly IMachOSectionSignatureTransferData? SectionSignatureTransferData;
      public readonly byte[]? Entitlements;
      public readonly byte[]? EntitlementsDer;

      public LoadCommandsInfo(bool hasSignature, MachOUtil.SignatureType signatureType, SignatureData signatureData, IEnumerable<HashVerificationUnit> hashVerificationUnits, IEnumerable<CDHash> cdHashes, IMachOSectionSignatureTransferData? sectionSignatureTransferData, byte[]? entitlements, byte[]? entitlementsDer)
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

    public static unsafe LoadCommandsInfo ReadLoadCommands(MachOFile.Section section, MachOUtil.Mode mode = MachOUtil.Mode.Default)
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
      MachOUtil.SignatureType signatureType = MachOUtil.SignatureType.None;
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

            if ((mode & MachOUtil.Mode.SignatureData) == MachOUtil.Mode.SignatureData)
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
              if (csLength > GetU4(ldc.datasize))
                throw new FormatException("Too big Mach-O code signature super blob");

              var csCount = EndianUtil.GetBeU4(cssb.count);
              if (csCount > (csLength - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex))
                throw new FormatException("Too many Mach-O code signature super blob entries");

              fixed (byte* scBuf = StreamUtil.ReadBytes(sectionStream, checked((int)csLength - sizeof(CS_SuperBlob))))
              {
                ComputeHashInfo[] specialSlotPositions = new ComputeHashInfo[(uint)CSSLOT.CSSLOT_HASHABLE_ENTRIES_MAX];

                for (int superBlobEntryIndex = 0; superBlobEntryIndex < csCount; superBlobEntryIndex++)
                {
                  var scPtr = scBuf + superBlobEntryIndex * sizeof(CS_BlobIndex);
                  CS_BlobIndex csbi;
                  MemoryUtil.CopyBytes(scPtr, (byte*)&csbi, sizeof(CS_BlobIndex));
                  var slotType = (CSSLOT)EndianUtil.GetBeU4(csbi.type);

                  if (slotType >= CSSLOT.CSSLOT_INFOSLOT && slotType <= CSSLOT.CSSLOT_LIBRARY_CONSTRAINT)
                  {
                    uint offset = EndianUtil.GetBeU4(csbi.offset);
                    var csbLength = GetBlobLength(scBuf, csLength, offset, sizeof(CS_Blob));

                    specialSlotPositions[(uint)slotType - 1] = new ComputeHashInfo(0,
                      new[]
                        {
                          new StreamRange(checked(imageOffset + GetU4(ldc.dataoff) + offset), csbLength)
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
                      var cscdLength = GetBlobLength(scBuf, csLength, offset, sizeof(CS_CodeDirectory));
                      CS_CodeDirectory cscd;
                      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&cscd, sizeof(CS_CodeDirectory));
                      if ((CSMAGIC)EndianUtil.GetBeU4(cscd.magic) != CSMAGIC.CSMAGIC_CODEDIRECTORY)
                        throw new FormatException("Invalid Mach-O code directory signature magic");

                      uint codeSlots = EndianUtil.GetBeU4(cscd.nCodeSlots);
                      uint specialSlots = EndianUtil.GetBeU4(cscd.nSpecialSlots);
                      uint zeroHashOffset = EndianUtil.GetBeU4(cscd.hashOffset);
                      long codeLimit = EndianUtil.GetBeU4(cscd.codeLimit);
                      if (cscd.hashSize == 0)
                        throw new FormatException("Invalid Mach-O code directory hash size");
                      if (zeroHashOffset > cscdLength || specialSlots > zeroHashOffset / cscd.hashSize || codeSlots > (cscdLength - zeroHashOffset) / cscd.hashSize)
                        throw new FormatException("Invalid Mach-O code directory hash slots");
                      if (cscd.pageSize > 30)
                        throw new FormatException("Invalid Mach-O code directory page size");
                      int pageSize = cscd.pageSize > 0 ? 1 << cscd.pageSize : 0;
                      if (pageSize > 0 && codeSlots > 0 && (long)(codeSlots - 1) * pageSize > codeLimit)
                        throw new FormatException("Invalid Mach-O code directory code limit");
                      string hashName = CS_HASHTYPE.GetHashName(cscd.hashType);

                      byte[] currentCodeDirectoryBlob = MemoryUtil.CopyBytes(csOffsetPtr, (int)cscdLength);
                      if (signatureType == MachOUtil.SignatureType.None)
                        signatureType = MachOUtil.SignatureType.AdHoc;

                      if (slotType == CSSLOT.CSSLOT_CODEDIRECTORY)
                        codeDirectoryBlob = currentCodeDirectoryBlob;

                      var cdHash = new CDHash(hashName,
                        new ComputeHashInfo(0,
                          new[]
                            {
                              new StreamRange(checked(imageOffset + GetU4(ldc.dataoff) + offset), cscdLength)
                            },
                          0));

                      cdHashes.Add(cdHash);

                      for (uint i = 0; i < codeSlots; i++)
                      {
                        byte[] hash = new byte[cscd.hashSize];
                        Array.Copy(currentCodeDirectoryBlob, (int)(zeroHashOffset + i * cscd.hashSize), hash, 0, cscd.hashSize);

                        long pageStart = (long)i * pageSize;
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
                        Array.Copy(currentCodeDirectoryBlob, (int)(zeroHashOffset - i * cscd.hashSize), hash, 0, cscd.hashSize);

                        if (i <= specialSlotPositions.Length && specialSlotPositions[i - 1] != null)
                          hashVerificationUnits.Add(new HashVerificationUnit(hashName, hash, specialSlotPositions[i - 1]));
                      }
                    }
                    break;
                  case CSSLOT.CSSLOT_CMS_SIGNATURE:
                    {
                      var csbLength = GetBlobLength(scBuf, csLength, offset, sizeof(CS_Blob));
                      CS_Blob csb;
                      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csb, sizeof(CS_Blob));
                      if ((CSMAGIC)EndianUtil.GetBeU4(csb.magic) != CSMAGIC.CSMAGIC_BLOBWRAPPER)
                        throw new FormatException("Invalid Mach-O blob wrapper signature magic");
                      cmsSignatureBlob = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Blob), (int)csbLength - sizeof(CS_Blob));
                      signatureType = MachOUtil.SignatureType.Regular;
                    }
                    break;
                  case CSSLOT.CSSLOT_ENTITLEMENTS:
                    {
                      var csentLength = GetBlobLength(scBuf, csLength, offset, sizeof(CS_Entitlements));
                      CS_Entitlements csent;
                      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csent, sizeof(CS_Entitlements));

                      CSMAGIC entitlementsMagic = (CSMAGIC)EndianUtil.GetBeU4(csent.magic);
                      if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS)
                        throw new FormatException($"Invalid Mach-O entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                      entitlements = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Entitlements), (int)csentLength - sizeof(CS_Entitlements));
                    }
                    break;
                  case CSSLOT.CSSLOT_ENTITLEMENTS_DER:
                    {
                      var csentLength = GetBlobLength(scBuf, csLength, offset, sizeof(CS_Entitlements));
                      CS_Entitlements csent;
                      MemoryUtil.CopyBytes(csOffsetPtr, (byte*)&csent, sizeof(CS_Entitlements));

                      CSMAGIC entitlementsMagic = (CSMAGIC)EndianUtil.GetBeU4(csent.magic);
                      if (entitlementsMagic != CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER)
                        throw new FormatException($"Invalid Mach-O der-encoded entitlements magic. Expected {CSMAGIC.CSMAGIC_EMBEDDED_ENTITLEMENTS_DER.ToString("X")} but got {entitlementsMagic.ToString("X")}");

                      entitlementsDer = MemoryUtil.CopyBytes(csOffsetPtr + sizeof(CS_Entitlements), (int)csentLength - sizeof(CS_Entitlements));
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
        (mode & MachOUtil.Mode.SignatureData) == MachOUtil.Mode.SignatureData && signatureType != MachOUtil.SignatureType.None ? sectionSignatureTransferData : null,
        entitlements,
        entitlementsDer);
    }

    private static unsafe uint GetBlobLength(byte* scBuf, uint csLength, uint offset, int minLength)
    {
      if (offset < sizeof(CS_SuperBlob) || offset > csLength || csLength - offset < sizeof(CS_Blob))
        throw new FormatException("Invalid Mach-O code signature blob offset");
      CS_Blob csb;
      MemoryUtil.CopyBytes(scBuf + offset - sizeof(CS_SuperBlob), (byte*)&csb, sizeof(CS_Blob));
      var length = EndianUtil.GetBeU4(csb.length);
      if (length < minLength || length > csLength - offset)
        throw new FormatException("Invalid Mach-O code signature blob length");
      return length;
    }

    public sealed class Symbol
    {
      public readonly string Name;
      public readonly NT Type;
      public readonly byte SectionIndex;
      public readonly ND Description;
      public readonly ulong Value;
      public readonly DelegateUtil.CreateStreamDelegate? CreateStream;

      internal Symbol(
        string name,
        NT type,
        byte sectionIndex,
        ND description,
        ulong value,
        DelegateUtil.CreateStreamDelegate? createStream)
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
      public readonly DelegateUtil.CreateStreamDelegate? CreateSection;

      internal DataSection(
        string sectionName,
        string segmentName,
        ulong address,
        ulong size,
        SEC flags,
        DelegateUtil.CreateStreamDelegate? createSection)
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

      var symtab = ReadSymtabCommand(section);
      if (symtab == null)
        return true;

      var symCount = checked((int)GetU4(symtab.Value.nsyms));
      var strSize = GetU4(symtab.Value.strsize);

      var is64 = section.Is64;
      var entrySize = is64 ? sizeof(nlist_64) : sizeof(nlist);

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
        if (is64)
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

        if (!symbolFilter(MakeSymbol(dataSections, ReadName(strStream, nStrX), nType, nSect, nDesc, nValue)))
          return false;
      }

      return true;
    }

    /// <summary>
    /// Looks for the external symbol with the given name, the local symbols and the debugging entries are skipped and the
    /// empty name is never found. The symbol definition is preferred to the undefined reference, then the lower symbol index
    /// wins. The name-sorted groups of the external and undefined symbols from <see cref="LC.LC_DYSYMTAB"/> are binary
    /// searched when it is present and the image is linked by Apple ld, otherwise the symbol table is scanned. The
    /// <paramref name="dataSections"/> are the ones returned by <see cref="ReadDataSections"/> for the same
    /// <paramref name="section"/>. The parsed stream should stay opened while the <see cref="Symbol.CreateStream"/> delegate
    /// is in use.
    /// </summary>
    public static bool TryGetSymbol(MachOFile.Section section, List<DataSection> dataSections, string name, [NotNullWhen(true)] out Symbol? symbol)
    {
      if (TryGetSymbolByDySymTab(section, dataSections, name, out symbol) == null)
        TryGetSymbolLinear(section, dataSections, name, out symbol);
      return symbol != null;
    }

    internal static unsafe bool? TryGetSymbolByDySymTab(MachOFile.Section section, List<DataSection> dataSections, string name, out Symbol? symbol)
    {
      symbol = null;
      var symtab = ReadSymtabCommand(section);
      if (symtab == null)
        return false;

      var needSwap = NeedSwap(section.Endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

      dysymtab_command? dysymtab = null;
      foreach (var command in section.Commands)
        if (command.Type == LC.LC_DYSYMTAB)
        {
          using var cmdStream = command.CreateStream();
          dysymtab_command dstc;
          StreamUtil.ReadBytes(cmdStream, (byte*)&dstc, sizeof(dysymtab_command));
          if ((LC)GetU4(dstc.cmd) != LC.LC_DYSYMTAB)
            throw new FormatException($"Invalid {nameof(dysymtab_command)} type");
          if (GetU4(dstc.cmdsize) < sizeof(dysymtab_command))
            throw new FormatException($"Invalid {nameof(dysymtab_command)} size");
          dysymtab = dstc;
          break;
        }

      // Note: the external symbols are grouped by module instead of the sorting by name when the table of contents is present
      if (dysymtab == null || GetU4(dysymtab.Value.tocoff) != 0)
        return null;

      // Note: only Apple ld sorts the symbol groups by name as loader.h describes, lld and Zig don't because the modern dyld
      // looks the exported symbols up in the export trie
      if (!IsLinkedByAppleLd(section))
        return null;

      using var table = new SymbolTable(section, dataSections, symtab.Value, name);
      var iExtDefSym = GetU4(dysymtab.Value.iextdefsym);
      var nExtDefSym = GetU4(dysymtab.Value.nextdefsym);
      var iUndefSym = GetU4(dysymtab.Value.iundefsym);
      var nUndefSym = GetU4(dysymtab.Value.nundefsym);
      if ((ulong)iExtDefSym + nExtDefSym > table.Count || (ulong)iUndefSym + nUndefSym > table.Count)
        throw new FormatException($"Invalid {nameof(dysymtab_command)} symbol groups");

      // Note: the undefined symbols are in the order they were seen by the static linker when MH_BINDATLOAD is set
      var entry = table.FindSorted(iExtDefSym, nExtDefSym, true) ??
                  ((section.MhFlags & MH_Flags.MH_BINDATLOAD) == 0
                    ? table.FindSorted(iUndefSym, nUndefSym, false)
                    : table.FindLinear(iUndefSym, nUndefSym, false));
      if (entry == null)
        return false;

      symbol = table.MakeSymbol(entry.Value);
      return true;
    }

    internal static bool TryGetSymbolLinear(MachOFile.Section section, List<DataSection> dataSections, string name, out Symbol? symbol)
    {
      symbol = null;
      var symtab = ReadSymtabCommand(section);
      if (symtab == null)
        return false;

      using var table = new SymbolTable(section, dataSections, symtab.Value, name);
      var entry = table.FindLinear(0, table.Count, true) ?? table.FindLinear(0, table.Count, false);
      if (entry == null)
        return false;

      symbol = table.MakeSymbol(entry.Value);
      return true;
    }

    private static unsafe symtab_command? ReadSymtabCommand(MachOFile.Section section)
    {
      var needSwap = NeedSwap(section.Endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

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
          return stc;
        }

      return null;
    }

    private static unsafe bool IsLinkedByAppleLd(MachOFile.Section section)
    {
      var needSwap = NeedSwap(section.Endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

      foreach (var command in section.Commands)
        if (command.Type == LC.LC_BUILD_VERSION)
        {
          using var cmdStream = command.CreateStream();
          build_version_command bvc;
          StreamUtil.ReadBytes(cmdStream, (byte*)&bvc, sizeof(build_version_command));
          if ((LC)GetU4(bvc.cmd) != LC.LC_BUILD_VERSION)
            throw new FormatException($"Invalid {nameof(build_version_command)} type");
          var nTools = GetU4(bvc.ntools);
          if (GetU4(bvc.cmdsize) < (uint)sizeof(build_version_command) + (ulong)nTools * (uint)sizeof(build_tool_version))
            throw new FormatException($"Invalid {nameof(build_version_command)} size");
          for (var n = 0u; n < nTools; ++n)
          {
            build_tool_version btv;
            StreamUtil.ReadBytes(cmdStream, (byte*)&btv, sizeof(build_tool_version));
            if ((TOOL)GetU4(btv.tool) == TOOL.TOOL_LD)
              return true;
          }
        }

      return false;
    }

    // Note: nlist.h defines the name of the zero string index as "" whatever the string table starts with
    private static string ReadName(Stream strStream, uint nStrX)
    {
      if (nStrX == 0)
        return "";
      strStream.Position = nStrX;
      return ReadStringZ(strStream);
    }

    private static Symbol MakeSymbol(List<DataSection> dataSections, string name, NT nType, byte nSect, ND nDesc, ulong nValue)
    {
      DelegateUtil.CreateStreamDelegate? createStream = null;
      if ((nType & NT.N_STAB) == 0 && (nType & NT.N_TYPE) == NT.N_SECT)
      {
        if (nSect == 0 || nSect >= dataSections.Count)
          throw new FormatException("Invalid Mach-O symbol section number");

        var headerDataSection = dataSections[0];
        var data = nSect == 1 && headerDataSection.Address <= nValue && nValue < headerDataSection.Address + headerDataSection.Size
          ? headerDataSection
          : dataSections[nSect];
        // Note: __mh_execute_header of MH_DSYM refers to the header which isn't recreated, so it is out of the section
        if (data.CreateSection != null && data.Address <= nValue && nValue - data.Address <= data.Size)
          createStream = MakeCreateStream(data, nValue);
      }

      return new Symbol(name, nType, nSect, nDesc, nValue, createStream);

      static DelegateUtil.CreateStreamDelegate MakeCreateStream(DataSection data, ulong nValue)
      {
        var offset = checked((long)(nValue - data.Address));
        var size = checked((long)(data.Address + data.Size - nValue));
        return () => new ReadOnlyNestedStream(data.CreateSection!(), offset, size);
      }
    }

    private readonly struct Entry
    {
      internal readonly uint Index;
      internal readonly uint Name;
      internal readonly NT Type;
      internal readonly byte Section;
      internal readonly ND Desc;
      internal readonly ulong Value;

      internal Entry(uint index, uint name, NT type, byte section, ND desc, ulong value)
      {
        Index = index;
        Name = name;
        Type = type;
        Section = section;
        Desc = desc;
        Value = value;
      }

      internal bool IsExternal => (Type & NT.N_STAB) == 0 && (Type & NT.N_EXT) != 0;
      internal bool IsDefined => (Type & NT.N_TYPE) is NT.N_ABS or NT.N_SECT or NT.N_INDR;
    }

    private sealed class SymbolTable : IDisposable
    {
      private const int ChunkEntryCount = 1024;

      private readonly List<DataSection> myDataSections;
      private readonly bool myNeedSwap;
      private readonly bool myIs64;
      private readonly int myEntrySize;
      private readonly uint myStrSize;
      private readonly Stream mySectionStream;
      private readonly Stream mySymStream;
      private readonly Stream myStrStream;
      private readonly byte[] myEntryBuffer;
      private readonly byte[] myName;
      private readonly byte[] myNameBuffer;
      internal readonly uint Count;

      internal unsafe SymbolTable(MachOFile.Section section, List<DataSection> dataSections, symtab_command symtab, string name)
      {
        myDataSections = dataSections;
        myNeedSwap = NeedSwap(section.Endian);
        myIs64 = section.Is64;
        myEntrySize = myIs64 ? sizeof(nlist_64) : sizeof(nlist);
        myStrSize = GetU4(symtab.strsize);
        Count = GetU4(symtab.nsyms);

        mySectionStream = section.CreateStream();
        myStrStream = new ReadOnlyNestedStream(mySectionStream, GetU4(symtab.stroff), myStrSize);
        mySymStream = new ReadOnlyNestedStream(mySectionStream, GetU4(symtab.symoff), checked((long)Count * myEntrySize));
        myEntryBuffer = new byte[myEntrySize];
        myName = Encoding.UTF8.GetBytes(name);
        myNameBuffer = new byte[myName.Length + 1];
      }

      public void Dispose()
      {
        mySymStream.Dispose();
        myStrStream.Dispose();
        mySectionStream.Dispose();
      }

      internal Entry? FindSorted(uint start, uint count, bool isDefined)
      {
        var lo = start;
        var hi = start + count;
        while (lo < hi)
        {
          var mid = lo + (hi - lo) / 2;
          if (Compare(Read(mid)) > 0)
            lo = mid + 1;
          else
            hi = mid;
        }

        for (var index = lo; index < start + count; ++index)
        {
          var entry = Read(index);
          if (!IsName(entry))
            break;
          if (entry.IsExternal && entry.IsDefined == isDefined)
            return entry;
        }

        return null;
      }

      internal unsafe Entry? FindLinear(uint start, uint count, bool isDefined)
      {
        var buffer = new byte[ChunkEntryCount * myEntrySize];
        mySymStream.Position = (long)start * myEntrySize;
        for (var index = start; index < start + count;)
        {
          var chunkCount = (int)Math.Min(ChunkEntryCount, start + count - index);
          StreamUtil.Read(mySymStream, buffer, 0, chunkCount * myEntrySize);
          fixed (byte* ptr = buffer)
            for (var n = 0; n < chunkCount; ++n, ++index)
            {
              var entry = Decode(index, ptr + n * myEntrySize);
              if (entry.IsExternal && entry.IsDefined == isDefined && IsName(entry))
                return entry;
            }
        }

        return null;
      }

      internal Symbol MakeSymbol(in Entry entry) =>
        MachOUtil.MakeSymbol(myDataSections, ReadName(myStrStream, CheckName(entry.Name)), entry.Type, entry.Section, entry.Desc, entry.Value);

      private unsafe Entry Read(uint index)
      {
        mySymStream.Position = (long)index * myEntrySize;
        StreamUtil.Read(mySymStream, myEntryBuffer, 0, myEntrySize);
        fixed (byte* ptr = myEntryBuffer)
          return Decode(index, ptr);
      }

      private unsafe Entry Decode(uint index, byte* ptr)
      {
        if (myIs64)
        {
          nlist_64 nl;
          MemoryUtil.CopyBytes(ptr, (byte*)&nl, sizeof(nlist_64));
          return new Entry(index, GetU4(nl.n_strx), (NT)nl.n_type, nl.n_sect, (ND)GetU2(nl.n_desc), GetU8(nl.n_value));
        }
        else
        {
          nlist nl;
          MemoryUtil.CopyBytes(ptr, (byte*)&nl, sizeof(nlist));
          return new Entry(index, GetU4(nl.n_strx), (NT)nl.n_type, nl.n_sect, (ND)GetU2(nl.n_desc), GetU4(nl.n_value));
        }
      }

      private bool IsName(in Entry entry) => myName.Length != 0 && Compare(entry) == 0;

      private int Compare(in Entry entry)
      {
        var nStrX = CheckName(entry.Name);
        if (nStrX == 0)
          return myName.Length == 0 ? 0 : 1;
        myStrStream.Position = nStrX;
        return StreamUtil.CompareStringZ(myStrStream, myName, myNameBuffer);
      }

      private uint CheckName(uint nStrX) => nStrX <= myStrSize ? nStrX : throw new FormatException("Invalid Mach-O symbol name index");

      private ushort GetU2(ushort v) => myNeedSwap ? EndianUtil.SwapU2(v) : v;
      private uint GetU4(uint v) => myNeedSwap ? EndianUtil.SwapU4(v) : v;
      private ulong GetU8(ulong v) => myNeedSwap ? EndianUtil.SwapU8(v) : v;
    }

    /// <summary>
    /// Reads the data sections of the Mach-O image. The declared sections are placed at their <c>n_sect</c> numbers, so
    /// the returned list starts with the recreated hidden __TEXT,__mach_header section. The mach header with the load commands
    /// is placed by the linker into the hidden __TEXT,__mach_header section, which is never emitted into the section table.
    /// The __mh_execute_header symbol still refers to it through n_sect==1, so the section is recreated here. The empty
    /// section without the data takes its place when there is no segment with the header data, e.g. in MH_OBJECT and MH_DSYM.
    /// The sections without the data in the file, like the zero-fill ones or the ones out of the segment file range, have no
    /// <see cref="DataSection.CreateSection"/>.
    /// </summary>
    public static unsafe List<DataSection> ReadDataSections(MachOFile.Section machOSection)
    {
      var needSwap = NeedSwap(machOSection.Endian);
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      var headerSize = (ulong)(sizeof(uint) /* magic */ + (machOSection.Is64 ? sizeof(mach_header_64) : sizeof(mach_header))) + machOSection.SizeOfLoadCommands;

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
                (SEC)GetU4(sec.flags),
                GetU4(sc.fileoff),
                GetU4(sc.filesize)));
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
                (SEC)GetU4(sec.flags),
                GetU8(sc.fileoff),
                GetU8(sc.filesize)));
            }
          }
          break;
        }

      dataSections.Insert(0, headerDataSection ?? new DataSection("__mach_header", "", 0, 0, SEC.S_REGULAR, null));
      return dataSections;

      static DataSection? MakeHeaderDataSection(MachOFile.Section machOSection, string segmentName, ulong address, ulong fileOffset, ulong fileSize, ulong headerSize)
      {
        if (fileOffset == 0 && fileSize >= headerSize)
          return MakeDataSection(machOSection, "__mach_header", segmentName, address, headerSize, 0, SEC.S_REGULAR, fileOffset, fileSize);
        return null;
      }

      static DataSection MakeDataSection(MachOFile.Section machOSection, string sectionName, string segmentName, ulong address, ulong size, ulong fileOffset, SEC flags, ulong segmentFileOffset, ulong segmentFileSize)
      {
        // Note: MH_DSYM keeps the sections of __TEXT and __DATA without the data, their segments have no file size
        var hasData = !IsZeroFill(flags) && segmentFileOffset <= fileOffset && size <= segmentFileSize && fileOffset - segmentFileOffset <= segmentFileSize - size;
        return new DataSection(sectionName, segmentName, address, size, flags, hasData
          ? new DelegateUtil.CreateStreamDelegate(() => new ReadOnlyNestedStream(machOSection.CreateStream(), checked((long)fileOffset), checked((long)size)))
          : null);
      }

      static string GetName(byte* buf, int nameSize)
      {
        var blob = MemoryUtil.CopyBytes(buf, nameSize);
        return new string(Encoding.UTF8.GetChars(blob, 0, MemoryUtil.GetAsciiStringZSize(blob)));
      }
    }

    public static bool IsZeroFill(SEC flags) => (flags & SEC.SECTION_TYPE) is SEC.S_ZEROFILL or SEC.S_GB_ZEROFILL or SEC.S_THREAD_LOCAL_ZEROFILL;

    public static IMachOSignatureTransferData? ReadSignatureTransferData(MachOFile machOFile, Mode mode = Mode.SignatureData)
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
  }
}
