using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using JetBrains.FormatRipper.Elf;
using JetBrains.Tests;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed partial class ElfFileTest
  {
    public sealed class Program
    {
      public readonly string Hash;
      public readonly ulong Size;
      public readonly PT Type;
      public readonly PF Flags;

      internal Program(string hash, ulong size, PT type, PF flags)
      {
        Hash = hash;
        Size = size;
        Type = type;
        Flags = flags;
      }

      public override string ToString() => $"{Hash}, {Size}, {Type}, {Flags}";
    }

    public sealed class Section
    {
      public readonly string? Hash;
      public readonly ulong Size;
      public readonly ulong Address;
      public readonly ulong AddressAlign;
      public readonly ulong EntSize;
      public readonly string Name;
      public readonly SHT Type;
      public readonly SHF Flags;
      public readonly ushort Link;
      public readonly uint Info;

      internal Section(string? hash, ulong size, ulong address, ulong addressAlign, ulong entSize, string name, SHT type, ushort link, uint info, SHF flags)
      {
        Hash = hash;
        Size = size;
        Address = address;
        AddressAlign = addressAlign;
        EntSize = entSize;
        Name = name;
        Type = type;
        Link = link;
        Info = info;
        Flags = flags;
      }

      public override string ToString() => $"{Hash}, {Size}, 0x{Address:X}, 0x{AddressAlign:X}, {EntSize}, \"{Name}\", {Type}, {Flags}, {Link}, 0x{Info:X}";
    }

    public sealed class Symbol
    {
      public readonly string? Hash;
      public readonly ulong Size;
      public readonly ulong Value;
      public readonly ushort SectionIndex;
      public readonly string Name;
      public readonly STT Type;
      public readonly STB Binding;
      public readonly byte Other;

      internal Symbol(string? hash, ulong size, ulong value, SHN sectionIndex, string name, STT type, STB binding, byte other) :
        this(hash, size, value, (ushort)sectionIndex, name, type, binding, other)
      {
      }

      internal Symbol(string? hash, ulong size, ulong value, ushort sectionIndex, string name, STT type, STB binding, byte other)
      {
        Hash = hash;
        Size = size;
        Value = value;
        SectionIndex = sectionIndex;
        Name = name;
        Type = type;
        Binding = binding;
        Other = other;
      }

      public override string ToString() => $"{Name}, {Size}, 0x{Value:X}, {SectionIndex}, \"{Name}\", {Type}, {Binding}, 0x{Other:X}";
    }

    private static object?[] Make(
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      byte expectedEiAbiVersion,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      int expectedDynSymCount,
      int expectedSymTabCount,
      Program[] expectedPrograms,
      Section[] expectedSections,
      Symbol[] expectedDynSymSymbols,
      Symbol[] expectedSymTabSymbols,
      Dictionary<string, string> expectedDynSymStrings,
      Dictionary<string, string> expectedSymTabStrings) => new object?[]
        {
          false,
          resourceName,
          expectedEiClass,
          expectedEiData,
          expectedEiOsAbi,
          expectedEiAbiVersion,
          expectedEType,
          expectedEMachine,
          expectedEFlags,
          expectedInterpreter,
          expectedDynSymCount,
          expectedSymTabCount,
          expectedPrograms,
          expectedSections,
          expectedDynSymSymbols,
          expectedSymTabSymbols,
          expectedDynSymStrings,
          expectedSymTabStrings
        };

    private static object?[] MakeOptional(
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      byte expectedEiAbiVersion,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      int expectedDynSymCount,
      int expectedSymTabCount,
      Program[] expectedPrograms,
      Section[] expectedSections,
      Symbol[] expectedDynSymSymbols,
      Symbol[] expectedSymTabSymbols,
      Dictionary<string, string> expectedDynSymStrings,
      Dictionary<string, string> expectedSymTabStrings) => new object?[]
        {
          true,
          resourceName,
          expectedEiClass,
          expectedEiData,
          expectedEiOsAbi,
          expectedEiAbiVersion,
          expectedEType,
          expectedEMachine,
          expectedEFlags,
          expectedInterpreter,
          expectedDynSymCount,
          expectedSymTabCount,
          expectedPrograms,
          expectedSections,
          expectedDynSymSymbols,
          expectedSymTabSymbols,
          expectedDynSymStrings,
          expectedSymTabStrings
        };

    [TestCaseSource(typeof(ElfFileTest), nameof(Sources))]
    [Test]
    public void Test(
      bool canIgnoreMissingResource,
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      byte expectedEiAbiVersion,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      int expectedDynSymCount,
      int expectedSymTabCount,
      Program[] expectedPrograms,
      Section[] expectedSections,
      Symbol[] expectedDynSymSymbols,
      Symbol[] expectedSymTabSymbols,
      Dictionary<string, string> expectedDynSymStrings,
      Dictionary<string, string> expectedSymTabStrings)
    {
      TestDataUtil.OpenRead(ResourceCategory.Elf, resourceName, stream =>
        {
          var file = ElfFile.Parse(stream);

          Assert.AreEqual(expectedEiClass, file.EiClass);
          Assert.AreEqual(expectedEiData, file.EiData);
          Assert.AreEqual(expectedEiOsAbi, file.EiOsAbi);
          Assert.AreEqual(expectedEiAbiVersion, file.EiAbiVersion);
          Assert.AreEqual(expectedEType, file.EType);
          Assert.AreEqual(expectedEMachine, file.EMachine);
          Assert.AreEqual(expectedEFlags, file.EFlags, $"Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
          Assert.AreEqual(expectedInterpreter, ElfUtil.GetInterp(file.Programs));

          var programs = file.Programs;
          Assert.AreEqual(expectedPrograms.Length, programs.Length);
          for (var n = 0; n < expectedPrograms.Length; ++n)
          {
            var expectedProgram = expectedPrograms[n];
            var program = programs[n];

            Assert.AreEqual(expectedProgram.Size, program.Size);
            Assert.AreEqual(expectedProgram.Type, program.Type);
            Assert.AreEqual(expectedProgram.Flags, program.Flags, $"Expected 0x{expectedProgram.Flags:X}, but was 0x{program.Flags:X}");

            var hash = CalculateStreamHash(() => program.CreateStream());
            Assert.AreEqual(expectedProgram.Hash, hash);
          }

          var sections = file.Sections;
          Assert.AreEqual(expectedSections.Length, sections.Length);
          for (var n = 0; n < expectedSections.Length; ++n)
          {
            var expectedSection = expectedSections[n];
            var section = sections[n];

            Assert.AreEqual(expectedSection.Name, section.Name);
            Assert.AreEqual(expectedSection.Size, section.Size);
            Assert.AreEqual(expectedSection.Address, section.Address, $"Expected 0x{expectedSection.Address:X}, but was 0x{section.Address:X}");
            Assert.AreEqual(expectedSection.AddressAlign, section.AddressAlign, $"Expected 0x{expectedSection.AddressAlign:X}, but was 0x{section.AddressAlign:X}");
            Assert.AreEqual(expectedSection.Type, section.Type);
            Assert.AreEqual(expectedSection.Flags, section.Flags, $"Expected 0x{expectedSection.Flags:X}, but was 0x{section.Flags:X}");
            Assert.AreEqual(expectedSection.Link, section.Link);
            Assert.AreEqual(expectedSection.Info, section.Info);
            Assert.AreEqual(expectedSection.EntSize, section.EntSize);

            var hash = section.Type == SHT.SHT_NOBITS ? null : CalculateStreamHash(() => section.CreateStream());
            Assert.AreEqual(expectedSection.Hash, hash);
          }

          AssertSymbols(file, SHT.SHT_DYNSYM, expectedDynSymCount, expectedDynSymSymbols, expectedDynSymStrings);
          AssertSymbols(file, SHT.SHT_SYMTAB, expectedSymTabCount, expectedSymTabSymbols, expectedSymTabStrings);
        }, str =>
        {
          if (canIgnoreMissingResource)
            Assert.Ignore(str);
        });
    }

    private static void AssertSymbols(ElfFile file, SHT symSectionType, int expectedSymbolCount, Symbol[] expectedSymbols, Dictionary<string, string> expectedStrings)
    {
      var symSectionIndex = ElfUtil.Find(file.Sections, symSectionType);
      var symbols = new List<ElfUtil.Symbol>(expectedSymbolCount);
      if (symSectionIndex == null)
        Assert.IsFalse(TryGetSymbol(file, symSectionType, "any", out _));
      else
        Assert.IsTrue(ElfUtil.GetSymbols(file, symSectionIndex.Value, file.Sections[symSectionIndex.Value].Link, symbol =>
          {
            symbols.Add(symbol);
            return true;
          }));
      Assert.AreEqual(expectedSymbolCount, symbols.Count, $"Unexpected {symSectionType} symbol count");

      var verifiedSymbols = SymbolUtil.SelectEdges(symbols);
      Assert.AreEqual(expectedSymbols.Length, verifiedSymbols.Length);
      for (var n = 0; n < expectedSymbols.Length; ++n)
      {
        var expectedSymbol = expectedSymbols[n];
        var symbol = verifiedSymbols[n];

        Assert.AreEqual(expectedSymbol.Name, symbol.Name);
        Assert.AreEqual(expectedSymbol.Size, symbol.Size);
        Assert.AreEqual(expectedSymbol.Value, symbol.Value, $"Expected 0x{expectedSymbol.Value:X}, but was 0x{symbol.Value:X}");
        Assert.AreEqual(expectedSymbol.SectionIndex, symbol.SectionIndex, $"Expected {expectedSymbol.SectionIndex}, but was {symbol.SectionIndex}");
        Assert.AreEqual(expectedSymbol.Type, symbol.Type);
        Assert.AreEqual(expectedSymbol.Binding, symbol.Binding);
        Assert.AreEqual(expectedSymbol.Other, symbol.Other);

        var hash = symbol.CreateStream == null ? null : CalculateStreamHash(() => symbol.CreateStream());
        Assert.AreEqual(expectedSymbol.Hash, hash);
      }

      SymbolUtil.AssertLookups(CheckLookups(file, symSectionType, symSectionIndex, symbols, SymbolUtil.MakeLookups(symbols, x => x.Name, IsGlobal, IsDefined), symbols.Count <= SymbolUtil.MaxLinearLookupSymbolCount));
      SymbolUtil.AssertStrings(expectedStrings, name => TryGetSymbol(file, symSectionType, name, out var symbol) ? symbol!.CreateStream : null, ElfUtil.ReadStringZ);
    }

    private static bool TryGetSymbol(ElfFile file, SHT symSectionType, string name, out ElfUtil.Symbol? symbol) =>
      symSectionType switch
        {
          SHT.SHT_DYNSYM => ElfUtil.TryGetDynamicSymbol(file, name, out symbol),
          SHT.SHT_SYMTAB => ElfUtil.TryGetStaticSymbol(file, name, out symbol),
          _ => throw new ArgumentOutOfRangeException(nameof(symSectionType), symSectionType, null)
        };

    private static bool IsGlobal(ElfUtil.Symbol symbol) => symbol.Binding != STB.STB_LOCAL;

    private static bool IsDefined(ElfUtil.Symbol symbol) => (SHN)symbol.SectionIndex != SHN.SHN_UNDEF;

    private static List<string> CheckLookups(ElfFile file, SHT symSectionType, ushort? symSectionIndex, IList<ElfUtil.Symbol> symbols, IEnumerable<Lookup> lookups, bool withLinear)
    {
      var errors = new List<string>();
      var tryGetSymbolBySectionType = symSectionType switch
        {
          SHT.SHT_DYNSYM => nameof(ElfUtil.TryGetDynamicSymbol),
          SHT.SHT_SYMTAB => nameof(ElfUtil.TryGetStaticSymbol),
          _ => throw new ArgumentOutOfRangeException(nameof(symSectionType), symSectionType, null)
        };
      foreach (var lookup in lookups)
      {
        var symIndex = symSectionIndex!.Value;
        var strIndex = file.Sections[symIndex].Link;
        var name = lookup.Name;
        Check(nameof(ElfUtil.TryGetSymbolBySectionIndexes), ElfUtil.TryGetSymbolBySectionIndexes(file, symIndex, strIndex, name, out var symbol), symbol);
        Check(tryGetSymbolBySectionType, TryGetSymbol(file, symSectionType, name, out symbol), symbol);
        Check(nameof(ElfUtil.TryGetSymbolByGnuHash), ElfUtil.TryGetSymbolByGnuHash(file, symIndex, strIndex, name, out symbol), symbol);
        Check(nameof(ElfUtil.TryGetSymbolBySysVHash), ElfUtil.TryGetSymbolBySysVHash(file, symIndex, strIndex, name, out symbol), symbol);
        if (withLinear)
          Check(nameof(ElfUtil.TryGetSymbolLinear), ElfUtil.TryGetSymbolLinear(file, symIndex, strIndex, name, out symbol), symbol);

        void Check(string method, bool? isFound, ElfUtil.Symbol? found)
        {
          if (isFound != null && CheckLookup(lookup, symbols, method, isFound.Value, found) is { } error)
            errors.Add(error);
        }
      }

      return errors;
    }

    private static string? CheckLookup(Lookup lookup, IList<ElfUtil.Symbol> symbols, string method, bool isFound, ElfUtil.Symbol? symbol)
    {
      var expectedSymbol = lookup.Index == null ? null : symbols[lookup.Index.Value];
      if (isFound != (expectedSymbol != null) || isFound != (symbol != null))
        return $"{method}(\"{lookup.Name}\") returned {isFound}, but the expected symbol index is {lookup.Index?.ToString() ?? "null"}";
      if (expectedSymbol == null || symbol == null)
        return null;

      var error = $"{method}(\"{lookup.Name}\") returned \"{symbol.Name}\" at 0x{symbol.Value:X}, but the expected symbol {lookup.Index} is \"{expectedSymbol.Name}\" at 0x{expectedSymbol.Value:X}";
      if (symbol.Name != expectedSymbol.Name || symbol.Size != expectedSymbol.Size || symbol.Value != expectedSymbol.Value || symbol.SectionIndex != expectedSymbol.SectionIndex ||
          symbol.Type != expectedSymbol.Type || symbol.Binding != expectedSymbol.Binding || symbol.Other != expectedSymbol.Other ||
          (symbol.CreateStream == null) != (expectedSymbol.CreateStream == null))
        return error;
      if (symbol.CreateStream != null && expectedSymbol.CreateStream != null)
      {
        using var expectedStream = expectedSymbol.CreateStream();
        using var stream = symbol.CreateStream();
        if (expectedStream.Length != stream.Length)
          return error;
      }

      return null;
    }

    private static string CalculateStreamHash(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA256.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }
  }
}
