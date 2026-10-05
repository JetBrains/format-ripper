using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using JetBrains.FormatRipper.Elf.Impl;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Elf
{
  public static class ElfUtil
  {
    public static bool NeedSwap(ELFDATA eiData) => BitConverter.IsLittleEndian != eiData switch
      {
        ELFDATA.ELFDATA2LSB => true,
        ELFDATA.ELFDATA2MSB => false,
        _ => throw new FormatException("Invalid ELF data encoding")
      };

    public static string ReadStringZ(Stream stream) => StreamUtil.ReadStringZ(stream);

    public static ushort? Find(ElfFile.Program[] programs, PT type)
    {
      var length = checked((ushort)programs.Length);
      for (ushort n = 0; n < length; n++)
        if (programs[n].Type == type)
          return n;
      return null;
    }

    public static ushort? Find(ElfFile.Section[] sections, SHT type)
    {
      var length = checked((ushort)sections.Length);
      for (ushort n = 0; n < length; n++)
        if (sections[n].Type == type)
          return n;
      return null;
    }

    public static bool HasInterp(ElfFile.Program[] programs) => Find(programs, PT.PT_INTERP) != null;

    public static string? GetInterp(ElfFile.Program[] programs)
    {
      var interp = Find(programs, PT.PT_INTERP);
      if (interp == null)
        return null;
      using var stream = programs[interp.Value].CreateStream();
      return ReadStringZ(stream);
    }

    public sealed class Symbol
    {
      public readonly string Name;
      public readonly ushort SectionIndex;
      public readonly ulong Value;
      public readonly ulong Size;
      public readonly STT Type;
      public readonly STB Binding;
      public readonly byte Other;
      public readonly DelegateUtil.CreateStreamDelegate? CreateStream;

      internal Symbol(string name, ushort sectionIndex, ulong value, ulong size, STT type, STB binding, byte other, DelegateUtil.CreateStreamDelegate? createStream)
      {
        Name = name;
        Size = size;
        Value = value;
        Type = type;
        Binding = binding;
        Other = other;
        SectionIndex = sectionIndex;
        CreateStream = createStream;
      }
    }

    public delegate bool SymbolFilterDelegate(Symbol symbol);

    public static bool GetSymbols(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, SymbolFilterDelegate symbolFilter)
    {
      ValidateSymbolSectionIndexes(file, symSectionIndex, strSectionIndex);
      var tlsAddress = GetTlsAddress(file);
      return file.EiClass switch
        {
          ELFCLASS.ELFCLASS32 => Read32(file.EiData, file.EMachine, file.Sections, tlsAddress, symSectionIndex, strSectionIndex, symbolFilter),
          ELFCLASS.ELFCLASS64 => Read64(file.EiData, file.EMachine, file.Sections, tlsAddress, symSectionIndex, strSectionIndex, symbolFilter),
          _ => throw new FormatException("Invalid ELF class encoding")
        };

      static unsafe bool Read32(ELFDATA eiData, EM eMachine, ElfFile.Section[] sections, ulong? tlsAddress, ushort symSectionIndex, ushort strSectionIndex, SymbolFilterDelegate symbolFilter)
      {
        var symSection = sections[symSectionIndex];
        var strSection = sections[strSectionIndex];

        var needSwap = NeedSwap(eiData);
        ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;

        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf32_Sym);
        if (entrySize < sizeof(Elf32_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();
        var symCount = checked((int)symStream.Length / entrySize);
        for (var n = 0; n < symCount; ++n)
        {
          Elf32_Sym shdr;
          StreamUtil.ReadBytes(symStream, (byte*)&shdr, sizeof(Elf32_Sym));
          symStream.Seek(entrySize - sizeof(Elf32_Sym), SeekOrigin.Current);

          strStream.Position = GetU4(shdr.st_name);
          var str = ReadStringZ(strStream);

          if (!symbolFilter(MakeSymbol(sections, eMachine, tlsAddress, str, GetU2(shdr.st_shndx), GetU4(shdr.st_value), GetU4(shdr.st_size), shdr.st_info, shdr.st_other)))
            return false;
        }

        return true;
      }

      static unsafe bool Read64(ELFDATA eiData, EM eMachine, ElfFile.Section[] sections, ulong? tlsAddress, ushort symSectionIndex, ushort strSectionIndex, SymbolFilterDelegate symbolFilter)
      {
        var symSection = sections[symSectionIndex];
        var strSection = sections[strSectionIndex];

        var needSwap = NeedSwap(eiData);
        ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
        uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
        ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf64_Sym);
        if (entrySize < sizeof(Elf64_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();

        var symCount = checked((int)symStream.Length / entrySize);
        for (var n = 0; n < symCount; ++n)
        {
          Elf64_Sym shdr;
          StreamUtil.ReadBytes(symStream, (byte*)&shdr, sizeof(Elf64_Sym));
          symStream.Seek(entrySize - sizeof(Elf64_Sym), SeekOrigin.Current);

          strStream.Position = GetU4(shdr.st_name);
          var str = ReadStringZ(strStream);

          if (!symbolFilter(MakeSymbol(sections, eMachine, tlsAddress, str, GetU2(shdr.st_shndx), GetU8(shdr.st_value), GetU8(shdr.st_size), shdr.st_info, shdr.st_other)))
            return false;
        }

        return true;
      }
    }

    /// <summary>
    /// Looks for the global symbol with the given name, the local symbols are skipped and the empty name is never found.
    /// The symbol definition is preferred to the undefined reference, then the lower symbol index wins. The GNU or SysV hash
    /// table linked to the symbol table is used when it is present, otherwise the symbol table is scanned. The parsed stream
    /// should stay opened while the <see cref="Symbol.CreateStream"/> delegate is in use.
    /// </summary>
    internal static bool TryGetSymbolBySectionIndexes(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, string name, [NotNullWhen(true)] out Symbol? symbol)
    {
      ValidateSymbolSectionIndexes(file, symSectionIndex, strSectionIndex);
      using var table = new SymbolTable(file, symSectionIndex, strSectionIndex, name);
      return table.FindByGnuHash(out symbol) ??
             table.FindBySysVHash(out symbol) ??
             table.FindLinear(false, out symbol);
    }

    /// <summary>
    /// Looks for the global symbol with the given name in the dynamic symbol table (<see cref="SHT.SHT_DYNSYM"/>) using the
    /// rules of <see cref="TryGetSymbolBySectionIndexes"/>. Returns false when the file has no dynamic symbol table.
    /// </summary>
    public static bool TryGetDynamicSymbol(ElfFile file, string name, [NotNullWhen(true)] out Symbol? symbol) =>
      TryGetSymbolBySectionType(file, SHT.SHT_DYNSYM, name, out symbol);

    /// <summary>
    /// Looks for the global symbol with the given name in the static symbol table (<see cref="SHT.SHT_SYMTAB"/>) using the
    /// rules of <see cref="TryGetSymbolBySectionIndexes"/>. Returns false when the file has no static symbol table.
    /// </summary>
    public static bool TryGetStaticSymbol(ElfFile file, string name, [NotNullWhen(true)] out Symbol? symbol) =>
      TryGetSymbolBySectionType(file, SHT.SHT_SYMTAB, name, out symbol);

    private static bool TryGetSymbolBySectionType(ElfFile file, SHT symSectionType, string name, [NotNullWhen(true)] out Symbol? symbol)
    {
      if (Find(file.Sections, symSectionType) is not { } symSectionIndex)
      {
        symbol = null;
        return false;
      }

      return TryGetSymbolBySectionIndexes(file, symSectionIndex, file.Sections[symSectionIndex].Link, name, out symbol);
    }

    internal static bool? TryGetSymbolByGnuHash(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, string name, out Symbol? symbol)
    {
      ValidateSymbolSectionIndexes(file, symSectionIndex, strSectionIndex);
      using var table = new SymbolTable(file, symSectionIndex, strSectionIndex, name);
      return table.FindByGnuHash(out symbol);
    }

    internal static bool? TryGetSymbolBySysVHash(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, string name, out Symbol? symbol)
    {
      ValidateSymbolSectionIndexes(file, symSectionIndex, strSectionIndex);
      using var table = new SymbolTable(file, symSectionIndex, strSectionIndex, name);
      return table.FindBySysVHash(out symbol);
    }

    internal static bool TryGetSymbolLinear(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, string name, out Symbol? symbol)
    {
      ValidateSymbolSectionIndexes(file, symSectionIndex, strSectionIndex);
      using var table = new SymbolTable(file, symSectionIndex, strSectionIndex, name);
      return table.FindLinear(false, out symbol);
    }

    private static void ValidateSymbolSectionIndexes(ElfFile file, ushort symSectionIndex, ushort strSectionIndex)
    {
      if ((SHN)symSectionIndex <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)symSectionIndex || symSectionIndex >= file.Sections.Length)
        throw new ArgumentOutOfRangeException(nameof(symSectionIndex));
      if ((SHN)strSectionIndex <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)strSectionIndex || strSectionIndex >= file.Sections.Length)
        throw new ArgumentOutOfRangeException(nameof(strSectionIndex));
    }

    // Note: the TLS symbol value is the offset in the TLS template, except for the relocatable files where it is the offset in the section
    private static ulong? GetTlsAddress(ElfFile file) =>
      file.EType != ET.ET_REL && Find(file.Programs, PT.PT_TLS) is { } tls ? file.Programs[tls].VirtualAddress : null;

    private static Symbol MakeSymbol(ElfFile.Section[] sections, EM eMachine, ulong? tlsAddress, string name, ushort stShNdx, ulong stValue, ulong stSize, byte stInfo, byte stOther)
    {
      if ((SHN)stShNdx == SHN.SHN_XINDEX)
        throw new NotSupportedException("ELF extended symbol section index is not supported");
      var stType = (STT)(stInfo & 0xF);
      var address = stType == STT.STT_TLS && tlsAddress != null ? tlsAddress.Value + stValue : stValue;
      // Note: the bit 0 of the ARM function symbol value marks the Thumb code, the first instruction is at the even address
      if (eMachine == EM.EM_ARM && stType is STT.STT_FUNC or STT.STT_GNU_IFUNC)
        address &= ~1ul;
      DelegateUtil.CreateStreamDelegate? createStream = null;
      if (SHN.SHN_UNDEF < (SHN)stShNdx && (SHN)stShNdx < SHN.SHN_LORESERVE)
      {
        if (stShNdx >= sections.Length)
          throw new FormatException("Invalid ELF symbol section number");

        var data = sections[stShNdx];
        var isInSection = data.Address <= address && address <= data.Address + data.Size;
        if (stSize != 0)
        {
          if ((data.Flags & SHF.SHF_ALLOC) == 0)
            throw new FormatException("Invalid ELF symbol section flags: allocation is required");
          if (!isInSection)
            throw new FormatException("Invalid ELF symbol section address");
        }

        if (isInSection)
        {
          var stShNdxEnd = FindEndOfSectionSequenceIndex(sections, stShNdx, address + stSize);
          if (!HasNoBits(sections, stShNdx, stShNdxEnd))
          {
            var offset = checked((long)(address - data.Address));
            var size = checked((long)stSize);
            if (stShNdx + 1 == stShNdxEnd)
              createStream = () => new ReadOnlyNestedStream(data.CreateStream(), offset, size);
            else
            {
              var createStreams = CreateStreamDelegates(sections, stShNdx, stShNdxEnd);
              createStream = () => new ReadOnlyNestedStream(new ReadOnlyAggregatedStream(CreateStreams(createStreams)), offset, size);
            }
          }
        }
      }

      return new Symbol(name, stShNdx, stValue, stSize, stType, (STB)(stInfo >> 4), stOther, createStream);

      static bool HasNoBits(ElfFile.Section[] sectionItems, ushort startIndex, ushort endIndex)
      {
        for (var n = startIndex; n < endIndex; n++)
          if (sectionItems[n].Type == SHT.SHT_NOBITS)
            return true;
        return false;
      }

      static DelegateUtil.CreateStreamDelegate[] CreateStreamDelegates(ElfFile.Section[] sectionItems, ushort startIndex, ushort endIndex)
      {
        var createStreams = new DelegateUtil.CreateStreamDelegate[endIndex - startIndex];
        for (var index = startIndex; index < endIndex; index++)
          createStreams[index - startIndex] = sectionItems[index].CreateStream;
        return createStreams;
      }

      static Stream[] CreateStreams(DelegateUtil.CreateStreamDelegate[] createStreams)
      {
        var streams = new Stream[createStreams.Length];
        for (var n = 0; n < createStreams.Length; n++)
          streams[n] = createStreams[n]();
        return streams;
      }

      static ushort FindEndOfSectionSequenceIndex(ElfFile.Section[] fileSectionItems, ushort startIndex, ulong addressEnd)
      {
        var endIndex = startIndex;
        while (true)
        {
          var prev = fileSectionItems[endIndex++];
          if (addressEnd <= prev.Address + prev.Size)
            break;

          if (fileSectionItems.Length <= endIndex)
            throw new FormatException("Invalid ELF symbol overtake the section list count");
          var curr = fileSectionItems[endIndex];
          if ((curr.Flags & SHF.SHF_ALLOC) == 0)
            throw new FormatException("Invalid ELF symbol use unallocated section");
          if (prev.Address + prev.Size != curr.Address)
            throw new FormatException("Invalid ELF symbol overtake the section size");
        }

        return endIndex;
      }
    }

    private readonly struct Entry
    {
      internal readonly uint Index;
      internal readonly uint Name;
      internal readonly ulong Value;
      internal readonly ulong Size;
      internal readonly byte Info;
      internal readonly byte Other;
      internal readonly ushort SectionIndex;

      internal Entry(uint index, uint name, ulong value, ulong size, byte info, byte other, ushort sectionIndex)
      {
        Index = index;
        Name = name;
        Value = value;
        Size = size;
        Info = info;
        Other = other;
        SectionIndex = sectionIndex;
      }

      internal bool IsGlobal => (STB)(Info >> 4) != STB.STB_LOCAL;
      internal bool IsDefined => (SHN)SectionIndex != SHN.SHN_UNDEF;
    }

    private sealed class SymbolTable : IDisposable
    {
      private const int ChunkEntryCount = 1024;

      private readonly ElfFile.Section[] mySections;
      private readonly EM myEMachine;
      private readonly ulong? myTlsAddress;
      private readonly ushort mySymSectionIndex;
      private readonly ELFCLASS myEiClass;
      private readonly bool myNeedSwap;
      private readonly int myEntrySize;
      private readonly uint myCount;
      private readonly Stream mySymStream;
      private readonly Stream myStrStream;
      private readonly byte[] myEntryBuffer;
      private readonly byte[] myName;
      private readonly byte[] myNameBuffer;

      internal unsafe SymbolTable(ElfFile file, ushort symSectionIndex, ushort strSectionIndex, string name)
      {
        mySections = file.Sections;
        myEMachine = file.EMachine;
        myTlsAddress = GetTlsAddress(file);
        mySymSectionIndex = symSectionIndex;
        myEiClass = file.EiClass;
        myNeedSwap = NeedSwap(file.EiData);

        var minEntrySize = myEiClass switch
          {
            ELFCLASS.ELFCLASS32 => sizeof(Elf32_Sym),
            ELFCLASS.ELFCLASS64 => sizeof(Elf64_Sym),
            _ => throw new FormatException("Invalid ELF class encoding")
          };
        var symSection = mySections[symSectionIndex];
        myEntrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : minEntrySize;
        if (myEntrySize < minEntrySize)
          throw new FormatException("Invalid ELF symbol header size");

        mySymStream = symSection.CreateStream();
        myStrStream = mySections[strSectionIndex].CreateStream();
        myCount = checked((uint)(mySymStream.Length / myEntrySize));
        myEntryBuffer = new byte[myEntrySize];
        myName = Encoding.UTF8.GetBytes(name);
        myNameBuffer = new byte[myName.Length + 1];
      }

      public void Dispose()
      {
        mySymStream.Dispose();
        myStrStream.Dispose();
      }

      internal bool? FindByGnuHash(out Symbol? symbol)
      {
        var hashSectionIndex = FindLinkedSection(SHT.SHT_GNU_HASH);
        if (hashSectionIndex == null)
        {
          symbol = null;
          return null;
        }

        using (var hashStream = mySections[hashSectionIndex.Value].CreateStream())
        {
          var nBuckets = ReadU4(hashStream);
          var symOffset = ReadU4(hashStream);
          var bloomSize = ReadU4(hashStream);
          var bloomShift = ReadU4(hashStream);
          if (nBuckets != 0 && bloomSize != 0)
          {
            var wordSize = myEiClass == ELFCLASS.ELFCLASS32 ? sizeof(uint) : sizeof(ulong);
            if (4 * sizeof(uint) + (long)bloomSize * wordSize + (long)nBuckets * sizeof(uint) > hashStream.Length)
              throw new FormatException("Invalid ELF GNU hash table size");

            var wordBits = 8u * (uint)wordSize;
            var hash = GnuHash(myName);

            hashStream.Position = 4 * sizeof(uint) + hash / wordBits % bloomSize * wordSize;
            var word = wordSize == sizeof(uint) ? ReadU4(hashStream) : ReadU8(hashStream);
            var mask = 1ul << (int)(hash % wordBits) | 1ul << (int)((hash >> (int)(bloomShift % 32)) % wordBits);
            if ((word & mask) == mask)
            {
              var bucketsOffset = 4 * sizeof(uint) + (long)bloomSize * wordSize;
              hashStream.Position = bucketsOffset + hash % nBuckets * sizeof(uint);
              var chainsOffset = bucketsOffset + (long)nBuckets * sizeof(uint);
              for (var index = ReadU4(hashStream); index != 0 && index >= symOffset && index < myCount; ++index)
              {
                var position = chainsOffset + (long)(index - symOffset) * sizeof(uint);
                if (position + sizeof(uint) > hashStream.Length)
                  break;
                hashStream.Position = position;
                var chainHash = ReadU4(hashStream);
                if ((chainHash | 1) == (hash | 1))
                {
                  var entry = Read(index);
                  if (entry.IsGlobal && entry.IsDefined && IsName(entry))
                  {
                    symbol = MakeSymbol(entry);
                    return true;
                  }
                }

                if ((chainHash & 1) != 0)
                  break;
              }
            }
          }
        }

        // Note: the GNU hash table is guaranteed to contain the symbol definitions only, the undefined references are scanned
        return FindLinear(true, out symbol);
      }

      internal bool? FindBySysVHash(out Symbol? symbol)
      {
        var hashSectionIndex = FindLinkedSection(SHT.SHT_HASH);
        if (hashSectionIndex == null)
        {
          symbol = null;
          return null;
        }

        var hashSection = mySections[hashSectionIndex.Value];
        Entry? defined = null;
        Entry? undefined = null;
        using (var hashStream = hashSection.CreateStream())
        {
          // Note: Alpha and s390x use the 64-bit hash table entries
          var entrySize = hashSection.EntSize == sizeof(ulong) ? sizeof(ulong) : sizeof(uint);
          ulong ReadEntry() => entrySize == sizeof(uint) ? ReadU4(hashStream) : ReadU8(hashStream);

          var nBucket = ReadEntry();
          var nChain = ReadEntry();
          if (nBucket != 0)
          {
            hashStream.Position = checked((long)(2 + ElfHash(myName) % nBucket) * entrySize);
            var index = ReadEntry();
            for (var step = 0ul; index != 0 && step < nChain; ++step)
            {
              if (index >= myCount || index >= nChain)
                throw new FormatException("Invalid ELF hash table chain");

              // Note: the chain order is arbitrary, so the lowest symbol index is chosen explicitly
              var entry = Read((uint)index);
              if (entry.IsGlobal && (entry.IsDefined ? IsLower(entry, defined) : defined == null && IsLower(entry, undefined)) && IsName(entry))
                if (entry.IsDefined)
                  defined = entry;
                else
                  undefined = entry;

              hashStream.Position = checked((long)(2 + nBucket + index) * entrySize);
              index = ReadEntry();
            }
          }
        }

        var found = defined ?? undefined;
        if (found == null)
        {
          symbol = null;
          return false;
        }

        symbol = MakeSymbol(found.Value);
        return true;

        static bool IsLower(in Entry entry, Entry? best) => best == null || entry.Index < best.Value.Index;
      }

      internal unsafe bool FindLinear(bool undefinedOnly, [NotNullWhen(true)] out Symbol? symbol)
      {
        Entry? undefined = null;
        var buffer = new byte[ChunkEntryCount * myEntrySize];
        mySymStream.Position = 0;
        for (var index = 0u; index < myCount;)
        {
          var count = (int)Math.Min(ChunkEntryCount, myCount - index);
          StreamUtil.Read(mySymStream, buffer, 0, count * myEntrySize);
          fixed (byte* ptr = buffer)
            for (var n = 0; n < count; ++n, ++index)
            {
              var entry = Decode(index, ptr + n * myEntrySize);
              if (!entry.IsGlobal || (entry.IsDefined ? undefinedOnly : undefined != null) || !IsName(entry))
                continue;
              if (entry.IsDefined)
              {
                symbol = MakeSymbol(entry);
                return true;
              }

              undefined = entry;
            }
        }

        if (undefined == null)
        {
          symbol = null;
          return false;
        }

        symbol = MakeSymbol(undefined.Value);
        return true;
      }

      private ushort? FindLinkedSection(SHT type)
      {
        var length = checked((ushort)mySections.Length);
        for (ushort n = 0; n < length; n++)
          if (mySections[n].Type == type && mySections[n].Link == mySymSectionIndex)
            return n;
        return null;
      }

      private unsafe Entry Read(uint index)
      {
        mySymStream.Position = checked((long)index * myEntrySize);
        StreamUtil.Read(mySymStream, myEntryBuffer, 0, myEntrySize);
        fixed (byte* ptr = myEntryBuffer)
          return Decode(index, ptr);
      }

      private unsafe Entry Decode(uint index, byte* ptr)
      {
        if (myEiClass == ELFCLASS.ELFCLASS32)
        {
          Elf32_Sym sym;
          MemoryUtil.CopyBytes(ptr, (byte*)&sym, sizeof(Elf32_Sym));
          return new Entry(index, GetU4(sym.st_name), GetU4(sym.st_value), GetU4(sym.st_size), sym.st_info, sym.st_other, GetU2(sym.st_shndx));
        }
        else
        {
          Elf64_Sym sym;
          MemoryUtil.CopyBytes(ptr, (byte*)&sym, sizeof(Elf64_Sym));
          return new Entry(index, GetU4(sym.st_name), GetU8(sym.st_value), GetU8(sym.st_size), sym.st_info, sym.st_other, GetU2(sym.st_shndx));
        }
      }

      private bool IsName(in Entry entry)
      {
        if (myName.Length == 0)
          return false;
        myStrStream.Position = entry.Name;
        return StreamUtil.CompareStringZ(myStrStream, myName, myNameBuffer) == 0;
      }

      private Symbol MakeSymbol(in Entry entry)
      {
        myStrStream.Position = entry.Name;
        return ElfUtil.MakeSymbol(mySections, myEMachine, myTlsAddress, ReadStringZ(myStrStream), entry.SectionIndex, entry.Value, entry.Size, entry.Info, entry.Other);
      }

      private unsafe uint ReadU4(Stream stream)
      {
        uint value;
        StreamUtil.ReadBytes(stream, (byte*)&value, sizeof(uint));
        return GetU4(value);
      }

      private unsafe ulong ReadU8(Stream stream)
      {
        ulong value;
        StreamUtil.ReadBytes(stream, (byte*)&value, sizeof(ulong));
        return GetU8(value);
      }

      private ushort GetU2(ushort v) => myNeedSwap ? EndianUtil.SwapU2(v) : v;
      private uint GetU4(uint v) => myNeedSwap ? EndianUtil.SwapU4(v) : v;
      private ulong GetU8(ulong v) => myNeedSwap ? EndianUtil.SwapU8(v) : v;

      private static uint GnuHash(byte[] name)
      {
        var hash = 5381u;
        foreach (var b in name)
          hash = hash * 33 + b;
        return hash;
      }

      private static uint ElfHash(byte[] name)
      {
        var hash = 0u;
        foreach (var b in name)
        {
          hash = (hash << 4) + b;
          var high = hash & 0xF0000000;
          if (high != 0)
            hash ^= high >> 24;
          hash &= ~high;
        }

        return hash;
      }
    }
  }
}
