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

    public static ushort? Find(ElfFile.Program[] items, PT type)
    {
      var length = checked((ushort)items.Length);
      for (ushort n = 0; n < length; n++)
        if (items[n].Type == type)
          return n;
      return null;
    }

    public static ushort? Find(ElfFile.Section[] items, SHT type)
    {
      var length = checked((ushort)items.Length);
      for (ushort n = 0; n < length; n++)
        if (items[n].Type == type)
          return n;
      return null;
    }

    public static bool HasInterp(ElfFile.Program[] items) => Find(items, PT.PT_INTERP) != null;

    public static string? GetInterp(ElfFile.Program[] items)
    {
      var interp = Find(items, PT.PT_INTERP);
      if (interp == null)
        return null;
      using var stream = items[interp.Value].CreateStream();
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
      public readonly ElfFile.CreateStreamDelegate? CreateStream;

      internal Symbol(string name, ushort sectionIndex, ulong value, ulong size, STT type, STB binding, byte other, ElfFile.CreateStreamDelegate? createStream)
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

    public static Symbol[] GetSymbols(ElfFile file, ushort symSectionIndex, ushort strSectionIndex)
    {
      if ((SHN)symSectionIndex <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)symSectionIndex || symSectionIndex >= file.Sections.Length)
        throw new ArgumentOutOfRangeException(nameof(symSectionIndex));
      if ((SHN)strSectionIndex <= SHN.SHN_UNDEF || SHN.SHN_LORESERVE <= (SHN)strSectionIndex || strSectionIndex >= file.Sections.Length)
        throw new ArgumentOutOfRangeException(nameof(strSectionIndex));
      var symSection = file.Sections[symSectionIndex];
      var strSection = file.Sections[strSectionIndex];

      var needSwap = NeedSwap(file.EiData);
      ushort GetU2(ushort v) => needSwap ? EndianUtil.SwapU2(v) : v;
      uint GetU4(uint v) => needSwap ? EndianUtil.SwapU4(v) : v;
      ulong GetU8(ulong v) => needSwap ? EndianUtil.SwapU8(v) : v;

      unsafe Symbol[] Read32()
      {
        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf32_Sym);
        if (entrySize < sizeof(Elf32_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();
        var symCount = checked((int)symStream.Length / entrySize);
        var symbols = new Symbol[symCount];
        for (var n = 0; n < symCount; ++n)
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

          Symbol symbol;
          if (SHN.SHN_UNDEF < (SHN)stShNdx && (SHN)stShNdx < SHN.SHN_LORESERVE)
          {
            var sections = file.Sections;
            if (stShNdx >= sections.Length)
              throw new FormatException("Invalid ELF symbol section number");

            var data = sections[stShNdx];
            if ((data.Flags & SHF.SHF_ALLOC) == 0)
              throw new FormatException("Invalid ELF symbol section flags: allocation is required");
            if (stValue < data.Address || data.Address + data.Size < stValue)
              throw new FormatException("Invalid ELF symbol section address");

            var stShNdxEnd = FindEndOfSectionSequenceIndex(sections, stShNdx, stValue + stSize);
            if (HasNoBits(file.Sections, stShNdx, stShNdxEnd))
              symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null);
            else
            {
              var offset = checked((long)(stValue - data.Address));
              if (stShNdx + 1 == stShNdxEnd)
                symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(data.CreateStream(), offset, stSize));
              else
              {
                var createStreams = CreateStreamDelegates(sections, stShNdx, stShNdxEnd);
                symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(new ReadOnlyAggregatedStream(CreateStreams(createStreams)), offset, stSize));
              }
            }
          }
          else
            symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null);

          symbols[n] = symbol;
        }

        return symbols;
      }

      unsafe Symbol[] Read64()
      {
        var entrySize = symSection.EntSize != 0 ? checked((int)symSection.EntSize) : sizeof(Elf64_Sym);
        if (entrySize < sizeof(Elf64_Sym))
          throw new FormatException("Invalid ELF symbol header size");
        using var strStream = strSection.CreateStream();
        using var symStream = symSection.CreateStream();

        var symCount = checked((int)symStream.Length / entrySize);
        var symbols = new Symbol[symCount];
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

          Symbol symbol;
          if (SHN.SHN_UNDEF < (SHN)stShNdx && (SHN)stShNdx < SHN.SHN_LORESERVE)
          {
            var sections = file.Sections;
            if (stShNdx >= sections.Length)
              throw new FormatException("Invalid ELF symbol section number");

            var data = sections[stShNdx];
            if ((data.Flags & SHF.SHF_ALLOC) == 0)
              throw new FormatException("Invalid ELF symbol section flags: allocation is required");
            if (stValue < data.Address || data.Address + data.Size < stValue)
              throw new FormatException("Invalid ELF symbol section address");

            var stShNdxEnd = FindEndOfSectionSequenceIndex(sections, stShNdx, stValue + stSize);
            if (HasNoBits(file.Sections, stShNdx, stShNdxEnd))
              symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null);
            else
            {
              var offset = checked((long)(stValue - data.Address));
              if (stShNdx + 1 == stShNdxEnd)
                symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(data.CreateStream(), offset, checked((long)stSize)));
              else
              {
                var createStreams = CreateStreamDelegates(sections, stShNdx, stShNdxEnd);
                symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, () => new ReadOnlyNestedStream(new ReadOnlyAggregatedStream(CreateStreams(createStreams)), offset, checked((long)stSize)));
              }
            }
          }
          else
            symbol = new Symbol(str, stShNdx, stValue, stSize, stType, stBinding, stOther, null);

          symbols[i] = symbol;
        }

        return symbols;
      }

      return file.EiClass switch
        {
          ELFCLASS.ELFCLASS32 => Read32(),
          ELFCLASS.ELFCLASS64 => Read64(),
          _ => throw new FormatException("Invalid ELF class encoding")
        };

      static bool HasNoBits(ElfFile.Section[] sectionItems, ushort startIndex, ushort endIndex)
      {
        for (var n = startIndex; n < endIndex; n++)
          if (sectionItems[n].Type == SHT.SHT_NOBITS)
            return true;
        return false;
      }

      static ElfFile.CreateStreamDelegate[] CreateStreamDelegates(ElfFile.Section[] sectionItems, ushort startIndex, ushort endIndex)
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
  }
}