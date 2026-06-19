using System;
using System.Collections.Generic;
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

    public static string ReadStringZ(Stream stream)
    {
      var buffer = new List<byte>(16);
      for (int b; (b = stream.ReadByte()) > 0;)
        buffer.Add((byte)b);
      var blob = buffer.ToArray();
      return new string(Encoding.UTF8.GetChars(blob, 0, blob.Length));
    }

    public static ushort? Find(ElfFile.ProgramItem[] items, PT type)
    {
      var length = checked((ushort)items.Length);
      for (ushort n = 0; n < length; n++)
        if (items[n].Type == type)
          return n;
      return null;
    }

    public static ushort? Find(ElfFile.SectionItem[] items, SHT type)
    {
      var length = checked((ushort)items.Length);
      for (ushort n = 0; n < length; n++)
        if (items[n].Type == type)
          return n;
      return null;
    }

    public static bool HasInterp(ElfFile.ProgramItem[] items) => Find(items, PT.PT_INTERP) != null;

    public static string? GetInterp(ElfFile.ProgramItem[] items)
    {
      var interp = Find(items, PT.PT_INTERP);
      if (interp == null)
        return null;
      using var stream = items[interp.Value].CreateStream();
      return ReadStringZ(stream);
    }


    public sealed class SymbolItem
    {
      public readonly string Name;
      public readonly ushort SectionIndex;
      public readonly ulong Value;
      public readonly ulong Size;
      public readonly STT Type;
      public readonly STB Binding;
      public readonly byte Other;
      public readonly ElfFile.CreateStreamDelegate? CreateStream;

      internal SymbolItem(string name, ushort sectionIndex, ulong value, ulong size, STT type, STB binding, byte other, ElfFile.CreateStreamDelegate? createStream)
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

    public delegate bool EnumPredicateDelegate(SymbolItem item);

    public static bool EnumSymbols(ElfFile file, ushort symSectionNdx, ushort strSectionNdx, EnumPredicateDelegate predicate)
    {
      if ((SHN)symSectionNdx <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)symSectionNdx || symSectionNdx >= file.SectionItems.Length)
        throw new ArgumentOutOfRangeException(nameof(symSectionNdx));
      if ((SHN)strSectionNdx <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)strSectionNdx || strSectionNdx >= file.SectionItems.Length)
        throw new ArgumentOutOfRangeException(nameof(strSectionNdx));
      var symSection = file.SectionItems[symSectionNdx];
      var strSection = file.SectionItems[strSectionNdx];

      var needSwap = NeedSwap(file.EiData);
      ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      unsafe bool Read32()
      {
        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf32_Sym);
        if (entrySize < sizeof(Elf32_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();
        var symCount = symStream.Length / entrySize;
        for (var i = 0; i < symCount; i++)
        {
          Elf32_Sym shdr;
          StreamUtil.ReadBytes(symStream, (byte*)&shdr, sizeof(Elf32_Sym));
          symStream.Seek(entrySize - sizeof(Elf32_Sym), SeekOrigin.Current);

          strStream.Position = GetU4(shdr.st_name);
          var str = ReadStringZ(strStream);
          var stShNdx = GetU2(shdr.st_shndx);
          var stValue = GetU4(shdr.st_value);
          var stSize = GetU4(shdr.st_size);
          var stType = (STT)(shdr.st_info & 0xF);
          var stBinding = (STB)(shdr.st_info >> 4);
          var stOther = shdr.st_other;

          if (SHN.SHN_UNDEF < (SHN)stShNdx && (SHN)stShNdx < SHN.SHN_LORESERVE)
          {
            var sectionItems = file.SectionItems;
            if (stShNdx >= sectionItems.Length)
              throw new FormatException("Invalid ELF symbol section number");

            var data = sectionItems[stShNdx];
            if ((data.Flags & SHF.SHF_ALLOC) == 0)
              throw new FormatException("Invalid ELF symbol section flags: allocation is required");
            if (stValue < data.Address || data.Address + data.Size < stValue)
              throw new FormatException("Invalid ELF symbol section address");

            var stShNdxEnd = FindEndOfSectionSequenceIndex(sectionItems, stShNdx, stValue + stSize);
            if (HasNoBits(file.SectionItems, stShNdx, stShNdxEnd))
            {
              if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null)))
                return false;
            }
            else
            {
              var offset = checked((long)(stValue - data.Address));
              if (stShNdx + 1 == stShNdxEnd)
              {
                if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(data.CreateStream(), offset, stSize))))
                  return false;
              }
              else
              {
                var createStreams = CreateStreamDelegates(sectionItems, stShNdx, stShNdxEnd);
                if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(new ReadOnlyAggregatedStream(CreateStreams(createStreams)), offset, stSize))))
                  return false;
              }
            }
          }
          else if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null)))
            return false;
        }

        return true;
      }

      unsafe bool Read64()
      {
        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf64_Sym);
        if (entrySize < sizeof(Elf64_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();
        var symCount = symStream.Length / entrySize;
        for (var i = 0; i < symCount; i++)
        {
          Elf64_Sym shdr;
          StreamUtil.ReadBytes(symStream, (byte*)&shdr, sizeof(Elf64_Sym));
          symStream.Seek(entrySize - sizeof(Elf64_Sym), SeekOrigin.Current);

          strStream.Position = GetU4(shdr.st_name);
          var str = ReadStringZ(strStream);

          var stShNdx = GetU2(shdr.st_shndx);
          var stValue = GetU8(shdr.st_value);
          var stSize = GetU8(shdr.st_size);
          var stType = (STT)(shdr.st_info & 0xF);
          var stBinding = (STB)(shdr.st_info >> 4);
          var stOther = shdr.st_other;

          if (SHN.SHN_UNDEF < (SHN)stShNdx && (SHN)stShNdx < SHN.SHN_LORESERVE)
          {
            var sectionItems = file.SectionItems;
            if (stShNdx >= sectionItems.Length)
              throw new FormatException("Invalid ELF symbol section number");

            var data = sectionItems[stShNdx];
            if ((data.Flags & SHF.SHF_ALLOC) == 0)
              throw new FormatException("Invalid ELF symbol section flags: allocation is required");
            if (stValue < data.Address || data.Address + data.Size < stValue)
              throw new FormatException("Invalid ELF symbol section address");

            var stShNdxEnd = FindEndOfSectionSequenceIndex(sectionItems, stShNdx, stValue + stSize);
            if (HasNoBits(file.SectionItems, stShNdx, stShNdxEnd))
            {
              if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null)))
                return false;
            }
            else
            {
              var offset = checked((long)(stValue - data.Address));
              if (stShNdx + 1 == stShNdxEnd)
              {
                if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(data.CreateStream(), offset, checked((long)stSize)))))
                  return false;
              }
              else
              {
                var createStreams = CreateStreamDelegates(sectionItems, stShNdx, stShNdxEnd);
                if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(new ReadOnlyAggregatedStream(CreateStreams(createStreams)), offset, checked((long)stSize)))))
                  return false;
              }
            }
          }
          else if (!predicate(new SymbolItem(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null)))
            return false;
        }

        return true;
      }

      return file.EiClass switch
        {
          ELFCLASS.ELFCLASS32 => Read32(),
          ELFCLASS.ELFCLASS64 => Read64(),
          _ => throw new FormatException("Invalid ELF class encoding")
        };

      static bool HasNoBits(ElfFile.SectionItem[] sectionItems, ushort startIndex, ushort endIndex)
      {
        for (var n = startIndex; n < endIndex; n++)
          if (sectionItems[n].Type == SHT.SHT_NOBITS)
            return true;
        return false;
      }

      static ElfFile.CreateStreamDelegate[] CreateStreamDelegates(ElfFile.SectionItem[] sectionItems, ushort startIndex, ushort endIndex)
      {
        var createStreams = new ElfFile.CreateStreamDelegate[endIndex - startIndex];
        for (var index = startIndex; index < endIndex; index++)
          createStreams[index - startIndex] = sectionItems[index].CreateStream;
        return createStreams;
      }

      static Stream[] CreateStreams(ElfFile.CreateStreamDelegate[] createStreams)
      {
        var streams = new Stream[createStreams.Length];
        for (var n = 0; n < createStreams.Length; n++)
          streams[n] = createStreams[n]();
        return streams;
      }

      static ushort FindEndOfSectionSequenceIndex(ElfFile.SectionItem[] fileSectionItems, ushort startIndex, ulong addressEnd)
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
  }
}