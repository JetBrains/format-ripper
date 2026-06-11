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
    public sealed class ProgramStreamInfo
    {
      public readonly string Hash;
      public readonly ulong Size;
      public readonly PT Type;
      public readonly PF Flags;

      public ProgramStreamInfo(string hash, ulong size, PT type, PF flags)
      {
        Hash = hash;
        Size = size;
        Type = type;
        Flags = flags;
      }

      public override string ToString() => $"{Hash}, {Size}, {Type}, {Flags}";
    }

    public sealed class SectionStreamInfo
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

      public SectionStreamInfo(string? hash, ulong size, ulong address, ulong addressAlign, ulong entSize, string name, SHT type, ushort link, uint info, SHF flags)
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

    public sealed class SymbolStreamInfo
    {
      public readonly string? Hash;
      public readonly ulong Size;
      public readonly ulong Value;
      public readonly ushort SectionIndex;
      public readonly string Name;
      public readonly STT Type;
      public readonly STB Binding;
      public readonly byte Other;

      public SymbolStreamInfo(string? hash, ulong size, ulong value, SHN sectionIndex, string name, STT type, STB binding, byte other) :
        this(hash, size, value, (ushort)sectionIndex, name, type, binding, other)
      {
      }

      public SymbolStreamInfo(string? hash, ulong size, ulong value, ushort sectionIndex, string name, STT type, STB binding, byte other)
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

    private static object?[] MakeSource(
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      ProgramStreamInfo[]? expectedProgramInfos,
      SectionStreamInfo[]? expectedSectionInfos,
      SymbolStreamInfo[]? expectedSymbolInfos = null) => new object?[]
        {
          false,
          resourceName,
          expectedEiClass,
          expectedEiData,
          expectedEiOsAbi,
          expectedEType,
          expectedEMachine,
          expectedEFlags,
          expectedInterpreter,
          null,
          expectedProgramInfos,
          expectedSectionInfos,
          expectedSymbolInfos
        };

    private static object?[] MakeOptionalSource(
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      string? expectedUnityScriptingBackend,
      ProgramStreamInfo[]? expectedProgramInfos,
      SectionStreamInfo[]? expectedSectionInfos,
      SymbolStreamInfo[]? expectedSymbolInfos = null) => new object?[]
        {
          true,
          resourceName,
          expectedEiClass,
          expectedEiData,
          expectedEiOsAbi,
          expectedEType,
          expectedEMachine,
          expectedEFlags,
          expectedInterpreter,
          expectedUnityScriptingBackend,
          expectedProgramInfos,
          expectedSectionInfos,
          expectedSymbolInfos
        };

    [TestCaseSource(typeof(ElfFileTest), nameof(Sources))]
    [Test]
    public void Test(
      bool canIgnoreMissingResource,
      string resourceName,
      ELFCLASS expectedEiClass,
      ELFDATA expectedEiData,
      ELFOSABI expectedEiOsAbi,
      ET expectedEType,
      EM expectedEMachine,
      EF expectedEFlags,
      string? expectedInterpreter,
      string? expectedUnityScriptingBackend,
      ProgramStreamInfo[]? expectedProgramInfos,
      SectionStreamInfo[]? expectedSectionInfos,
      SymbolStreamInfo[]? expectedSymbolInfos)
    {
      ResourceUtil.OpenRead(ResourceCategory.Elf, resourceName, stream =>
        {
          Assert.IsTrue(ElfFile.Is(stream));
          var file = ElfFile.Parse(stream);

          Assert.AreEqual(expectedEiClass, file.EiClass);
          Assert.AreEqual(expectedEiData, file.EiData);
          Assert.AreEqual(expectedEiOsAbi, file.EiOsAbi);
          Assert.AreEqual(expectedEType, file.EType);
          Assert.AreEqual(expectedEMachine, file.EMachine);
          Assert.AreEqual(expectedEFlags, file.EFlags, $"Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
          Assert.AreEqual(expectedInterpreter, ElfUtil.GetInterp(file.ProgramItems));

          if (expectedProgramInfos != null)
          {
            var programItems = file.ProgramItems;
            Assert.AreEqual(expectedProgramInfos.Length, programItems.Length);
            for (var n = 0; n < expectedProgramInfos.Length; ++n)
            {
              var info = expectedProgramInfos[n];
              var item = programItems[n];

              var header = item.Header;
              Assert.AreEqual(info.Size, header.Size);
              Assert.AreEqual(info.Type, header.Type);
              Assert.AreEqual(info.Flags, header.Flags, $"Expected 0x{info.Flags:X}, but was 0x{header.Flags:X}");

              var hash = CalculateStreamHash(() => item.CreateStream());
              Assert.AreEqual(info.Hash, hash);
            }
          }
          else
            GenerateProgramStreamInfos(file);

          if (expectedSectionInfos != null)
          {
            var sectionItems = file.SectionItems;
            Assert.AreEqual(expectedSectionInfos.Length, sectionItems.Length);
            for (var k = 0; k < expectedSectionInfos.Length; ++k)
            {
              var info = expectedSectionInfos[k];
              var item = sectionItems[k];

              var header = item.Header;
              Assert.AreEqual(info.Name, header.Name);
              Assert.AreEqual(info.Size, header.Size);
              Assert.AreEqual(info.Address, header.Address, $"Expected 0x{info.Address:X}, but was 0x{header.Address:X}");
              Assert.AreEqual(info.AddressAlign, header.AddressAlign, $"Expected 0x{info.AddressAlign:X}, but was 0x{header.AddressAlign:X}");
              Assert.AreEqual(info.Type, header.Type);
              Assert.AreEqual(info.Flags, header.Flags, $"Expected 0x{info.Flags:X}, but was 0x{header.Flags:X}");
              Assert.AreEqual(info.Link, header.Link);
              Assert.AreEqual(info.Info, header.Info);
              Assert.AreEqual(info.EntSize, header.EntSize);

              var hash = header.Type == SHT.SHT_NOBITS ? null : CalculateStreamHash(() => item.CreateStream());
              Assert.AreEqual(info.Hash, hash);
            }
          }
          else
            GenerateSectionStreamInfos(file);

          string? unityScriptingBackend = null;
          var symbolItems = new List<ElfUtil.SymbolItem>();
          {
            var symSectionNdx = ElfUtil.Find(file.SectionItems, SHT.SHT_DYNSYM) ?? ElfUtil.Find(file.SectionItems, SHT.SHT_SYMTAB);
            if (symSectionNdx != null)
            {
              ElfUtil.EnumSymbols(file, symSectionNdx.Value, file.SectionItems[symSectionNdx.Value].Header.Link, symbolInfo =>
                {
                  var symbolInfoHeader = symbolInfo.Header;
                  if (symbolInfoHeader is { Type: STT.STT_OBJECT, Binding: STB.STB_GLOBAL, Name: UnityUtil.UNITY_SCRIPTING_BACKEND_ELF_SYMBOL })
                  {
                    using var dataStream = symbolInfo.CreateStream!();
                    unityScriptingBackend = ElfUtil.ReadStringZ(dataStream);
                  }

                  symbolItems.Add(symbolInfo);
                  return true;
                });
            }
          }

          if (expectedSymbolInfos != null)
          {
            Assert.AreEqual(expectedSymbolInfos.Length, symbolItems.Count);
            for (var k = 0; k < expectedSymbolInfos.Length; ++k)
            {
              var info = expectedSymbolInfos[k];
              var item = symbolItems[k];

              var header = item.Header;
              Assert.AreEqual(info.Name, header.Name);
              Assert.AreEqual(info.Size, header.Size);
              Assert.AreEqual(info.Value, header.Value, $"Expected 0x{info.Value:X}, but was 0x{header.Value:X}");
              Assert.AreEqual(info.SectionIndex, header.SectionIndex, $"Expected {info.SectionIndex}, but was {header.SectionIndex}");
              Assert.AreEqual(info.Type, header.Type);
              Assert.AreEqual(info.Binding, header.Binding);
              Assert.AreEqual(info.Other, header.Other);

              var hash =  item.CreateStream == null ? null : CalculateStreamHash(() => item.CreateStream());
              Assert.AreEqual(info.Hash, hash);
            }
          }
          else
            GenerateSymbolStreamInfos(symbolItems);

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

      var maxSizeLength = file.ProgramItems.Select(x => x.Header.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = file.ProgramItems.Select(x => ("PT." + Enum.GetName(typeof(PT), x.Header.Type)).Length).DefaultIfEmpty(0).Max();
      foreach (var programItem in file.ProgramItems)
      {
        var programItemHeader = programItem.Header;
        var hash = CalculateStreamHash(() => programItem.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}),",
          '"' + hash + '"',
          programItemHeader.Size.ToString().PadLeft(maxSizeLength),
          ("PT." + Enum.GetName(typeof(PT), programItemHeader.Type)).PadRight(maxTypeLength),
          GetStr(programItemHeader.Flags));
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
      var maxHashLength = file.SectionItems.Select(x => x.Header.Type == SHT.SHT_NOBITS ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxSizeLength = file.SectionItems.Select(x => x.Header.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxAddressLength = file.SectionItems.Select(x => ("0x" + x.Header.Address.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxAddressAlignLength = file.SectionItems.Select(x => ("0x" + x.Header.AddressAlign.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxNameLength = file.SectionItems.Select(x => x.Header.Name.Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = file.SectionItems.Select(x => ("SHT." + Enum.GetName(typeof(SHT), x.Header.Type)).Length).DefaultIfEmpty(0).Max();
      var maxEntSizeLength = file.SectionItems.Select(x => x.Header.EntSize.ToString().Length).DefaultIfEmpty(0).Max();
      var maxLinkLength = file.SectionItems.Select(x => x.Header.Link.ToString().Length).DefaultIfEmpty(0).Max();
      var maxInfoLength = file.SectionItems.Select(x => x.Header.Info.ToString().Length).DefaultIfEmpty(0).Max();
      foreach (var sectionItem in file.SectionItems)
      {
        var sectionItemHeader = sectionItem.Header;
        var hash = sectionItemHeader.Type == SHT.SHT_NOBITS ? null : CalculateStreamHash(() => sectionItem.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          sectionItemHeader.Size.ToString().PadLeft(maxSizeLength),
          ("0x" + sectionItemHeader.Address.ToString("X")).PadLeft(maxAddressLength),
          ("0x" + sectionItemHeader.AddressAlign.ToString("X")).PadLeft(maxAddressAlignLength),
          sectionItemHeader.EntSize.ToString().PadLeft(maxEntSizeLength),
          ('"' + sectionItemHeader.Name + '"').PadRight(maxNameLength + 2),
          ("SHT." + Enum.GetName(typeof(SHT), sectionItemHeader.Type)).PadRight(maxTypeLength),
          sectionItemHeader.Link.ToString().PadLeft(maxLinkLength),
          sectionItemHeader.Info.ToString().PadLeft(maxInfoLength),
          GetStr(sectionItemHeader.Flags));
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

    private static void GenerateSymbolStreamInfos(ICollection<ElfUtil.SymbolItem> symbolItems)
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
      var maxNameLength = symbolItems.Select(x => x.Header.Name.Length).DefaultIfEmpty(0).Max();
      var maxSizeLength = symbolItems.Select(x => x.Header.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxValueLength = symbolItems.Select(x => ("0x" + x.Header.Value.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxSectionIndexLength = symbolItems.Select(x => GetSectionIndexStr(x.Header.SectionIndex).Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = symbolItems.Select(x => ("STT." + Enum.GetName(typeof(STT), x.Header.Type)).Length).DefaultIfEmpty(0).Max();
      var maxBindingLength = symbolItems.Select(x => ("STB." + Enum.GetName(typeof(STB), x.Header.Binding)).Length).DefaultIfEmpty(0).Max();
      foreach (var symbolItem in symbolItems)
      {
        var symbolItemHeader = symbolItem.Header;
        var hash = symbolItem.CreateStream == null ? null : CalculateStreamHash(() => symbolItem.CreateStream());

        var sectionIndexStr = GetSectionIndexStr(symbolItemHeader.SectionIndex);
        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}, {6}, 0x{7:X}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          symbolItemHeader.Size.ToString().PadLeft(maxSizeLength),
          ("0x" + symbolItemHeader.Value.ToString("X")).PadLeft(maxValueLength),
          sectionIndexStr.StartsWith("SHN.") ? sectionIndexStr.PadRight(maxSectionIndexLength) : sectionIndexStr.PadLeft(maxSectionIndexLength),
          ('"' + symbolItemHeader.Name + '"').PadRight(maxNameLength + 2),
          ("STT." + Enum.GetName(typeof(STT), symbolItemHeader.Type)).PadRight(maxTypeLength),
          ("STB." + Enum.GetName(typeof(STB), symbolItemHeader.Binding)).PadRight(maxBindingLength),
          symbolItemHeader.Other);
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
