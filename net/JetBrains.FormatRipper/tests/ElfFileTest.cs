using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using JetBrains.FormatRipper.Elf;
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
      Program[]? expectedPrograms,
      Section[]? expectedSections,
      Symbol[]? expectedSymbols = null) => new object?[]
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
          null,
          expectedPrograms,
          expectedSections,
          expectedSymbols
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
      string? expectedUnityScriptingBackend,
      Program[]? expectedPrograms,
      Section[]? expectedSections,
      Symbol[]? expectedSymbols = null) => new object?[]
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
          expectedUnityScriptingBackend,
          expectedPrograms,
          expectedSections,
          expectedSymbols
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
      string? expectedUnityScriptingBackend,
      Program[]? expectedPrograms,
      Section[]? expectedSections,
      Symbol[]? expectedSymbols)
    {
      ResourceUtil.OpenRead(ResourceCategory.Elf, resourceName, stream =>
        {
          Assert.IsTrue(ElfFile.Is(stream));
          var file = ElfFile.Parse(stream);

          Assert.AreEqual(expectedEiClass, file.EiClass);
          Assert.AreEqual(expectedEiData, file.EiData);
          Assert.AreEqual(expectedEiOsAbi, file.EiOsAbi);
          Assert.AreEqual(expectedEiAbiVersion, file.EiAbiVersion);
          Assert.AreEqual(expectedEType, file.EType);
          Assert.AreEqual(expectedEMachine, file.EMachine);
          Assert.AreEqual(expectedEFlags, file.EFlags, $"Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
          Assert.AreEqual(expectedInterpreter, ElfUtil.GetInterp(file.Programs));

          if (expectedPrograms != null)
          {
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
          }
          else
            GenerateProgramStreamInfos(file);

          if (expectedSections != null)
          {
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
          }
          else
            GenerateSectionStreamInfos(file);

          var symSectionIndex = ElfUtil.Find(file.Sections, SHT.SHT_DYNSYM) ?? ElfUtil.Find(file.Sections, SHT.SHT_SYMTAB);
          var symbols = symSectionIndex != null ? ElfUtil.GetSymbols(file, symSectionIndex.Value, file.Sections[symSectionIndex.Value].Link) : new ElfUtil.Symbol[0];

          if (expectedSymbols != null)
          {
            Assert.AreEqual(expectedSymbols.Length, symbols.Length);
            for (var n = 0; n < expectedSymbols.Length; ++n)
            {
              var expectedSymbol = expectedSymbols[n];
              var symbol = symbols[n];

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
          }
          else
            GenerateSymbolStreamInfos(symbols);

          string? unityScriptingBackend = null;
          foreach (var symbol in symbols)
            if (symbol is { Type: STT.STT_OBJECT, Binding: STB.STB_GLOBAL, Name: UnityUtil.UNITY_SCRIPTING_BACKEND_ELF_SYMBOL })
            {
              using var dataStream = symbol.CreateStream!();
              unityScriptingBackend = ElfUtil.ReadStringZ(dataStream);
              break;
            }
          Assert.AreEqual(expectedUnityScriptingBackend, unityScriptingBackend);
        }, str =>
        {
          if (canIgnoreMissingResource)
            Assert.Ignore(str);
        });
    }

    private const int Sha256HashStringLength = 2 * 256 / 8;

    private static string CalculateStreamHash(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA256.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }

    private static void GenerateProgramStreamInfos(ElfFile file)
    {
      Console.WriteLine("          new ProgramStreamInfo[]");
      Console.WriteLine("            {");

      var maxSizeLength = file.Programs.Select(x => x.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = file.Programs.Select(x => ("PT." + Enum.GetName(typeof(PT), x.Type)).Length).DefaultIfEmpty(0).Max();
      foreach (var programItem in file.Programs)
      {
        var hash = CalculateStreamHash(() => programItem.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}),",
          '"' + hash + '"',
          programItem.Size.ToString().PadLeft(maxSizeLength),
          ("PT." + Enum.GetName(typeof(PT), programItem.Type)).PadRight(maxTypeLength),
          GetStr(programItem.Flags));
      }
      Console.WriteLine("            },");

      static string GetStr(PF flags)
      {
        if (flags == 0)
          return "0";
        var builder = new StringBuilder();
        foreach (PF phFlag in Enum.GetValues(typeof(PF)))
        {
          var n = (uint)phFlag;
          if ((n & n - 1) != 0)
            continue;

          if (((uint)flags & n) == n)
          {
            if (builder.Length > 0)
              builder.Append(" | ");
            builder.Append("PF.").Append(Enum.GetName(typeof(PF), phFlag));
          }
        }
        return builder.ToString();
      }
    }

    private static void GenerateSectionStreamInfos(ElfFile file)
    {
      Console.WriteLine("          new SectionStreamInfo[]");
      Console.WriteLine("            {");

      const string @null = "null";
      var maxHashLength = file.Sections.Select(x => x.Type == SHT.SHT_NOBITS ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxSizeLength = file.Sections.Select(x => x.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxAddressLength = file.Sections.Select(x => ("0x" + x.Address.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxAddressAlignLength = file.Sections.Select(x => ("0x" + x.AddressAlign.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxNameLength = file.Sections.Select(x => x.Name.Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = file.Sections.Select(x => ("SHT." + Enum.GetName(typeof(SHT), x.Type)).Length).DefaultIfEmpty(0).Max();
      var maxEntSizeLength = file.Sections.Select(x => x.EntSize.ToString().Length).DefaultIfEmpty(0).Max();
      var maxLinkLength = file.Sections.Select(x => x.Link.ToString().Length).DefaultIfEmpty(0).Max();
      var maxInfoLength = file.Sections.Select(x => x.Info.ToString().Length).DefaultIfEmpty(0).Max();
      foreach (var sectionItem in file.Sections)
      {
        var hash = sectionItem.Type == SHT.SHT_NOBITS ? null : CalculateStreamHash(() => sectionItem.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          sectionItem.Size.ToString().PadLeft(maxSizeLength),
          ("0x" + sectionItem.Address.ToString("X")).PadLeft(maxAddressLength),
          ("0x" + sectionItem.AddressAlign.ToString("X")).PadLeft(maxAddressAlignLength),
          sectionItem.EntSize.ToString().PadLeft(maxEntSizeLength),
          ('"' + sectionItem.Name + '"').PadRight(maxNameLength + 2),
          ("SHT." + Enum.GetName(typeof(SHT), sectionItem.Type)).PadRight(maxTypeLength),
          sectionItem.Link.ToString().PadLeft(maxLinkLength),
          sectionItem.Info.ToString().PadLeft(maxInfoLength),
          GetStr(sectionItem.Flags));
      }
      Console.WriteLine("            },");

      static string GetStr(SHF flags)
      {
        if (flags == 0)
          return "0";
        var builder = new StringBuilder();
        foreach (SHF shFlag in Enum.GetValues(typeof(SHF)))
        {
          var n = (uint)shFlag;
          if ((n & n - 1) != 0)
            continue;

          if (((uint)flags & n) == n)
          {
            if (builder.Length > 0)
              builder.Append(" | ");
            builder.Append("SHF.").Append(Enum.GetName(typeof(SHF), shFlag));
          }
        }
        return builder.ToString();
      }
    }

    private static void GenerateSymbolStreamInfos(ICollection<ElfUtil.Symbol> symbolItems)
    {
      if (symbolItems.Count >= 128)
      {
        Console.WriteLine("Symbol count: {0}", symbolItems.Count);
        return;
      }

      Console.WriteLine("          new SymbolStreamInfo[]");
      Console.WriteLine("            {");

      const string @null = "null";
      var maxHashLength = symbolItems.Select(x => x.CreateStream == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxNameLength = symbolItems.Select(x => x.Name.Length).DefaultIfEmpty(0).Max();
      var maxSizeLength = symbolItems.Select(x => x.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxValueLength = symbolItems.Select(x => ("0x" + x.Value.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxSectionIndexLength = symbolItems.Select(x => GetSectionIndexStr(x.SectionIndex).Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = symbolItems.Select(x => ("STT." + Enum.GetName(typeof(STT), x.Type)).Length).DefaultIfEmpty(0).Max();
      var maxBindingLength = symbolItems.Select(x => ("STB." + Enum.GetName(typeof(STB), x.Binding)).Length).DefaultIfEmpty(0).Max();
      foreach (var symbolItem in symbolItems)
      {
        var hash = symbolItem.CreateStream == null ? null : CalculateStreamHash(() => symbolItem.CreateStream());

        var sectionIndexStr = GetSectionIndexStr(symbolItem.SectionIndex);
        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}, {6}, 0x{7:X}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          symbolItem.Size.ToString().PadLeft(maxSizeLength),
          ("0x" + symbolItem.Value.ToString("X")).PadLeft(maxValueLength),
          sectionIndexStr.StartsWith("SHN.") ? sectionIndexStr.PadRight(maxSectionIndexLength) : sectionIndexStr.PadLeft(maxSectionIndexLength),
          ('"' + symbolItem.Name + '"').PadRight(maxNameLength + 2),
          ("STT." + Enum.GetName(typeof(STT), symbolItem.Type)).PadRight(maxTypeLength),
          ("STB." + Enum.GetName(typeof(STB), symbolItem.Binding)).PadRight(maxBindingLength),
          symbolItem.Other);
      }

      Console.WriteLine("            },");

      static string GetSectionIndexStr(ushort sectionIndex)
      {
        var name = (SHN)sectionIndex == SHN.SHN_UNDEF || (SHN)sectionIndex > SHN.SHN_LORESERVE ? Enum.GetName(typeof(SHN), (SHN)sectionIndex) : null;
        return name != null ? "SHN." + name : sectionIndex.ToString();
      }
    }
  }
}
