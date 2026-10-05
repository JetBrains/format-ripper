using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using JetBrains.FormatRipper.Pe;
using JetBrains.Tests;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed partial class PeFileTest
  {
    [Flags]
    public enum CodeOptions
    {
      HasCmsBlob = 0x1,
      HasMetadata = 0x2
    }

    public sealed class Section
    {
      public readonly string? Hash;
      public readonly uint VirtualAddress;
      public readonly uint VirtualSize;
      public readonly uint SizeOfRawData;
      public readonly string Name;
      public readonly IMAGE_SCN Characteristics;

      internal Section(string? hash, uint virtualAddress, uint virtualSize, uint sizeOfRawData, string name, IMAGE_SCN characteristics)
      {
        Hash = hash;
        VirtualAddress = virtualAddress;
        VirtualSize = virtualSize;
        SizeOfRawData = sizeOfRawData;
        Name = name;
        Characteristics = characteristics;
      }

      public override string ToString() => $"{Hash}, 0x{VirtualAddress:X}, {VirtualSize}, {SizeOfRawData}, \"{Name}\", 0x{(uint)Characteristics:X}";
    }

    public sealed class Export
    {
      public readonly string? Hash;
      public readonly uint Ordinal;
      public readonly uint VirtualAddress;
      public readonly string? Name;
      public readonly string? Forwarder;

      internal Export(string? hash, uint ordinal, uint virtualAddress, string? name, string? forwarder)
      {
        Hash = hash;
        Ordinal = ordinal;
        VirtualAddress = virtualAddress;
        Name = name;
        Forwarder = forwarder;
      }

      public override string ToString() => $"{Hash}, {Ordinal}, 0x{VirtualAddress:X}, \"{Name}\", \"{Forwarder}\"";
    }

    public sealed class Symbol
    {
      public readonly string? Hash;
      public readonly uint Value;
      public readonly ushort SectionNumber;
      public readonly string Name;
      public readonly IMAGE_SYM_TYPE BaseType;
      public readonly IMAGE_SYM_DTYPE DerivedType;
      public readonly IMAGE_SYM_CLASS StorageClass;
      public readonly byte NumberOfAuxSymbols;

      internal Symbol(string? hash, uint value, IMAGE_SYM sectionNumber, string name, IMAGE_SYM_TYPE baseType, IMAGE_SYM_DTYPE derivedType, IMAGE_SYM_CLASS storageClass, byte numberOfAuxSymbols) :
        this(hash, value, (ushort)sectionNumber, name, baseType, derivedType, storageClass, numberOfAuxSymbols)
      {
      }

      internal Symbol(string? hash, uint value, ushort sectionNumber, string name, IMAGE_SYM_TYPE baseType, IMAGE_SYM_DTYPE derivedType, IMAGE_SYM_CLASS storageClass, byte numberOfAuxSymbols)
      {
        Hash = hash;
        Value = value;
        SectionNumber = sectionNumber;
        Name = name;
        BaseType = baseType;
        DerivedType = derivedType;
        StorageClass = storageClass;
        NumberOfAuxSymbols = numberOfAuxSymbols;
      }

      public override string ToString() => $"{Hash}, 0x{Value:X}, {SectionNumber}, \"{Name}\", {BaseType}, {DerivedType}, {StorageClass}, {NumberOfAuxSymbols}";
    }

    private static object?[] Make(
      string resourceName,
      IMAGE_FILE_MACHINE expectedMachine,
      IMAGE_SUBSYSTEM expectedSubsystem,
      IMAGE_FILE expectedCharacteristics,
      CodeOptions expectedOptions,
      string? expectedCmsBlobHash,
      string expectedSecurityDataDirectoryRange,
      string expectedOrderedIncludeRanges,
      int expectedExportCount,
      int expectedSymbolCount,
      Section[]? expectedSections,
      Export[]? expectedExports,
      Symbol[]? expectedSymbols = null) => new object?[]
        {
          false,
          resourceName,
          expectedMachine,
          expectedSubsystem,
          expectedCharacteristics,
          expectedOptions,
          expectedCmsBlobHash,
          expectedSecurityDataDirectoryRange,
          expectedOrderedIncludeRanges,
          null,
          expectedExportCount,
          expectedSymbolCount,
          expectedSections,
          expectedExports,
          expectedSymbols
        };

    private static object?[] MakeOptional(
      string resourceName,
      IMAGE_FILE_MACHINE expectedMachine,
      IMAGE_SUBSYSTEM expectedSubsystem,
      IMAGE_FILE expectedCharacteristics,
      CodeOptions expectedOptions,
      string? expectedCmsBlobHash,
      string expectedSecurityDataDirectoryRange,
      string expectedOrderedIncludeRanges,
      string? expectedUnityScriptingBackend,
      int expectedExportCount,
      int expectedSymbolCount,
      Section[]? expectedSections,
      Export[]? expectedExports,
      Symbol[]? expectedSymbols = null) => new object?[]
        {
          true,
          resourceName,
          expectedMachine,
          expectedSubsystem,
          expectedCharacteristics,
          expectedOptions,
          expectedCmsBlobHash,
          expectedSecurityDataDirectoryRange,
          expectedOrderedIncludeRanges,
          expectedUnityScriptingBackend,
          expectedExportCount,
          expectedSymbolCount,
          expectedSections,
          expectedExports,
          expectedSymbols
        };

    [TestCaseSource(typeof(PeFileTest), nameof(Sources))]
    [Test]
    public void Test(
      bool canIgnoreMissingResource,
      string resourceName,
      IMAGE_FILE_MACHINE expectedMachine,
      IMAGE_SUBSYSTEM expectedSubsystem,
      IMAGE_FILE expectedCharacteristics,
      CodeOptions expectedOptions,
      string? expectedCmsBlobHash,
      string expectedSecurityDataDirectoryRange,
      string expectedOrderedIncludeRanges,
      string? expectedUnityScriptingBackend,
      int expectedExportCount,
      int expectedSymbolCount,
      Section[]? expectedSections,
      Export[]? expectedExports,
      Symbol[]? expectedSymbols)
    {
      TestDataUtil.OpenRead(ResourceCategory.Pe, resourceName, stream =>
        {
          var file = PeFile.Parse(stream, PeFile.Mode.SignatureData | PeFile.Mode.ComputeHashInfo);

          Assert.AreEqual(expectedMachine, file.Machine);
          Assert.AreEqual(expectedCharacteristics, file.Characteristics, $"Expected 0x{expectedCharacteristics:X}, but was 0x{file.Characteristics:X}");
          Assert.AreEqual(expectedSubsystem, file.Subsystem);

          var hasCmsSignature = (expectedOptions & CodeOptions.HasCmsBlob) == CodeOptions.HasCmsBlob;
          var hasMetadata = (expectedOptions & CodeOptions.HasMetadata) == CodeOptions.HasMetadata;
          var signedBlob = file.SignatureData.SignedBlob;
          var cmsBlob = file.SignatureData.CmsBlob;

          Assert.AreEqual(hasCmsSignature, file.HasSignature);
          Assert.IsNull(signedBlob);
          Assert.AreEqual(hasCmsSignature, cmsBlob != null);

          if (cmsBlob != null)
          {
            byte[] hash;
            using (var hashAlgorithm = SHA384.Create())
              hash = hashAlgorithm.ComputeHash(cmsBlob);
            Assert.AreEqual(expectedCmsBlobHash, HexUtil.ConvertToHexString(hash));
          }
          else
            Assert.IsNull(expectedCmsBlobHash);

          Assert.AreEqual(hasMetadata, file.HasMetadata);
          Assert.AreEqual(expectedSecurityDataDirectoryRange, file.SecurityDataDirectoryRange.ToString());

          var computeHashInfo = file.ComputeHashInfo;
          Assert.IsNotNull(computeHashInfo);
          ValidateUtil.Validate(computeHashInfo!);
          Assert.AreEqual(expectedOrderedIncludeRanges, computeHashInfo!.ToString());

          if (expectedSections != null)
          {
            var sections = file.Sections;
            Assert.AreEqual(expectedSections.Length, sections.Length);
            for (var n = 0; n < expectedSections.Length; ++n)
            {
              var expectedSection = expectedSections[n];
              var section = sections[n];

              Assert.AreEqual(expectedSection.Name, section.Name);
              Assert.AreEqual(expectedSection.VirtualAddress, section.VirtualAddress, $"Expected 0x{expectedSection.VirtualAddress:X}, but was 0x{section.VirtualAddress:X}");
              Assert.AreEqual(expectedSection.VirtualSize, section.VirtualSize);
              Assert.AreEqual(expectedSection.SizeOfRawData, section.SizeOfRawData);
              Assert.AreEqual(expectedSection.Characteristics, section.Characteristics, $"Expected 0x{(uint)expectedSection.Characteristics:X}, but was 0x{(uint)section.Characteristics:X}");

              var hash = section.CreateStream == null ? null : CalculateStreamHash(() => section.CreateStream());
              Assert.AreEqual(expectedSection.Hash, hash);
            }
          }
          else
            GenerateSectionInfos(file.Sections);

          var exports = new List<PeUtil.Export>(expectedExportCount);
          Assert.IsTrue(PeUtil.GetExports(file, export =>
            {
              exports.Add(export);
              return true;
            }));
          Assert.AreEqual(expectedExportCount, exports.Count, "Unexpected export count");

          var verifiedExports = SymbolUtil.SelectEdges(exports);
          if (expectedExports != null)
          {
            Assert.AreEqual(expectedExports.Length, verifiedExports.Length);
            for (var n = 0; n < expectedExports.Length; ++n)
            {
              var expectedExport = expectedExports[n];
              var export = verifiedExports[n];

              Assert.AreEqual(expectedExport.Name, export.Name);
              Assert.AreEqual(expectedExport.Ordinal, export.Ordinal);
              Assert.AreEqual(expectedExport.VirtualAddress, export.VirtualAddress, $"Expected 0x{expectedExport.VirtualAddress:X}, but was 0x{export.VirtualAddress:X}");
              Assert.AreEqual(expectedExport.Forwarder, export.Forwarder);

              var hash = export.CreateStream == null ? null : CalculateStreamHash(() => export.CreateStream());
              Assert.AreEqual(expectedExport.Hash, hash);
            }
          }
          else
            GenerateExportInfos(verifiedExports);

          SymbolUtil.AssertLookups(CheckExportLookups(file, exports, SymbolUtil.MakeLookups(exports, x => x.Name, IsNamed, _ => true), exports.Count <= SymbolUtil.MaxLinearLookupSymbolCount));

          var symbols = new List<PeUtil.Symbol>(expectedSymbolCount);
          Assert.IsTrue(PeUtil.GetSymbols(file, symbol =>
            {
              symbols.Add(symbol);
              return true;
            }));
          Assert.AreEqual(expectedSymbolCount, symbols.Count, "Unexpected symbol count");

          var verifiedSymbols = SymbolUtil.SelectEdges(symbols);
          if (expectedSymbols != null)
          {
            Assert.AreEqual(expectedSymbols.Length, verifiedSymbols.Length);
            for (var n = 0; n < expectedSymbols.Length; ++n)
            {
              var expectedSymbol = expectedSymbols[n];
              var symbol = verifiedSymbols[n];

              Assert.AreEqual(expectedSymbol.Name, symbol.Name);
              Assert.AreEqual(expectedSymbol.Value, symbol.Value, $"Expected 0x{expectedSymbol.Value:X}, but was 0x{symbol.Value:X}");
              Assert.AreEqual(expectedSymbol.SectionNumber, symbol.SectionNumber, $"Expected 0x{expectedSymbol.SectionNumber:X}, but was 0x{symbol.SectionNumber:X}");
              Assert.AreEqual(expectedSymbol.BaseType, symbol.BaseType);
              Assert.AreEqual(expectedSymbol.DerivedType, symbol.DerivedType);
              Assert.AreEqual(expectedSymbol.StorageClass, symbol.StorageClass);
              Assert.AreEqual(expectedSymbol.NumberOfAuxSymbols, symbol.NumberOfAuxSymbols);

              var hash = symbol.CreateStream == null ? null : CalculateStreamHash(() => symbol.CreateStream());
              Assert.AreEqual(expectedSymbol.Hash, hash);
            }
          }
          else
            GenerateSymbolInfos(verifiedSymbols);

          SymbolUtil.AssertLookups(CheckSymbolLookups(file, symbols, SymbolUtil.MakeLookups(symbols, x => x.Name, IsExternal, IsDefined)));

          string? unityScriptingBackend = null;
          foreach (var export in exports)
            if (export is { Name: UnityUtil.UNITY_SCRIPTING_BACKEND_ELF_PE_SYMBOL, Forwarder: null })
            {
              using var dataStream = export.CreateStream!();
              unityScriptingBackend = PeUtil.ReadStringZ(dataStream);
              break;
            }

          if (unityScriptingBackend != null)
            Assert.Contains(unityScriptingBackend, new[]
              {
                UnityUtil.CORECLR_UNITY_SCRIPTING_BACKEND_VALUE,
                UnityUtil.IL2CPP_UNITY_SCRIPTING_BACKEND_VALUE,
                UnityUtil.MONO_UNITY_SCRIPTING_BACKEND_VALUE
              });
          Assert.AreEqual(expectedUnityScriptingBackend, unityScriptingBackend);
        }, str =>
        {
          if (canIgnoreMissingResource)
            Assert.Ignore(str);
        });
    }

    [TestCase("HelloWorld1_realigned.exe")]
    [TestCase("HelloWorld1_realigned_signed.exe")]
    [Test]
    public void SymbolsErrorTest(string resourceName)
    {
      TestDataUtil.OpenRead(ResourceCategory.Pe, resourceName, stream =>
        {
          var file = PeFile.Parse(stream);
          Assert.That(() => PeUtil.GetSymbols(file, _ => true), Throws.TypeOf<FormatException>());
        });
    }

    private static bool IsNamed(PeUtil.Export export) => export.Name != null;

    private static bool IsExternal(PeUtil.Symbol symbol) => symbol.StorageClass is IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_EXTERNAL or IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_WEAK_EXTERNAL;

    private static bool IsDefined(PeUtil.Symbol symbol) => (IMAGE_SYM)symbol.SectionNumber != IMAGE_SYM.IMAGE_SYM_UNDEFINED;

    private static List<string> CheckExportLookups(PeFile file, IList<PeUtil.Export> exports, IEnumerable<Lookup> lookups, bool withLinear)
    {
      var errors = new List<string>();
      foreach (var lookup in lookups)
      {
        Check(nameof(PeUtil.TryGetExport), PeUtil.TryGetExport(file, lookup.Name, out var export), export);
        if (withLinear)
          Check(nameof(PeUtil.TryGetExportLinear), PeUtil.TryGetExportLinear(file, lookup.Name, out export), export);

        void Check(string method, bool isFound, PeUtil.Export? found)
        {
          if (CheckExportLookup(lookup, exports, method, isFound, found) is { } error)
            errors.Add(error);
        }
      }

      return errors;
    }

    private static string? CheckExportLookup(Lookup lookup, IList<PeUtil.Export> exports, string method, bool isFound, PeUtil.Export? export)
    {
      var expectedExport = lookup.Index == null ? null : exports[lookup.Index.Value];
      if (isFound != (expectedExport != null) || isFound != (export != null))
        return $"{method}(\"{lookup.Name}\") returned {isFound}, but the expected export index is {lookup.Index?.ToString() ?? "null"}";
      if (expectedExport == null || export == null)
        return null;

      if (export.Name != expectedExport.Name || export.Ordinal != expectedExport.Ordinal || export.VirtualAddress != expectedExport.VirtualAddress ||
          export.Forwarder != expectedExport.Forwarder || !IsSameStream(expectedExport.CreateStream, export.CreateStream))
        return $"{method}(\"{lookup.Name}\") returned \"{export.Name}\" with ordinal {export.Ordinal}, but the expected export {lookup.Index} is \"{expectedExport.Name}\" with ordinal {expectedExport.Ordinal}";
      return null;
    }

    private static List<string> CheckSymbolLookups(PeFile file, IList<PeUtil.Symbol> symbols, IEnumerable<Lookup> lookups)
    {
      var errors = new List<string>();
      foreach (var lookup in lookups)
        if (CheckSymbolLookup(lookup, symbols, nameof(PeUtil.TryGetSymbol), PeUtil.TryGetSymbol(file, lookup.Name, out var symbol), symbol) is { } error)
          errors.Add(error);
      return errors;
    }

    private static string? CheckSymbolLookup(Lookup lookup, IList<PeUtil.Symbol> symbols, string method, bool isFound, PeUtil.Symbol? symbol)
    {
      var expectedSymbol = lookup.Index == null ? null : symbols[lookup.Index.Value];
      if (isFound != (expectedSymbol != null) || isFound != (symbol != null))
        return $"{method}(\"{lookup.Name}\") returned {isFound}, but the expected symbol index is {lookup.Index?.ToString() ?? "null"}";
      if (expectedSymbol == null || symbol == null)
        return null;

      if (symbol.Name != expectedSymbol.Name || symbol.Value != expectedSymbol.Value || symbol.SectionNumber != expectedSymbol.SectionNumber ||
          symbol.BaseType != expectedSymbol.BaseType || symbol.DerivedType != expectedSymbol.DerivedType || symbol.StorageClass != expectedSymbol.StorageClass ||
          symbol.NumberOfAuxSymbols != expectedSymbol.NumberOfAuxSymbols || !IsSameStream(expectedSymbol.CreateStream, symbol.CreateStream))
        return $"{method}(\"{lookup.Name}\") returned \"{symbol.Name}\" at 0x{symbol.Value:X}, but the expected symbol {lookup.Index} is \"{expectedSymbol.Name}\" at 0x{expectedSymbol.Value:X}";
      return null;
    }

    private static bool IsSameStream(DelegateUtil.CreateStreamDelegate? expectedCreateStream, DelegateUtil.CreateStreamDelegate? createStream)
    {
      if (expectedCreateStream == null || createStream == null)
        return expectedCreateStream == createStream;
      using var expectedStream = expectedCreateStream();
      using var stream = createStream();
      return expectedStream.Length == stream.Length;
    }

    private const int Sha256HashStringLength = 2 * 256 / 8;
    private const string @null = "null";

    private static string CalculateStreamHash(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA256.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }

    private static void GenerateSectionInfos(PeFile.Section[] sections)
    {
      if (sections.Length == 0)
      {
        Console.WriteLine("          new Section[] {},");
        return;
      }

      Console.WriteLine("          new Section[]");
      Console.WriteLine("            {");

      var maxHashLength = sections.Select(x => x.CreateStream == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxVirtualAddressLength = sections.Select(x => ("0x" + x.VirtualAddress.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxVirtualSizeLength = sections.Select(x => x.VirtualSize.ToString().Length).DefaultIfEmpty(0).Max();
      var maxSizeOfRawDataLength = sections.Select(x => x.SizeOfRawData.ToString().Length).DefaultIfEmpty(0).Max();
      var maxNameLength = sections.Select(x => x.Name.Length).DefaultIfEmpty(0).Max();
      foreach (var section in sections)
      {
        var hash = section.CreateStream == null ? null : CalculateStreamHash(() => section.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          ("0x" + section.VirtualAddress.ToString("X")).PadLeft(maxVirtualAddressLength),
          section.VirtualSize.ToString().PadLeft(maxVirtualSizeLength),
          section.SizeOfRawData.ToString().PadLeft(maxSizeOfRawDataLength),
          ('"' + section.Name + '"').PadRight(maxNameLength + 2),
          GetCharacteristicsStr(section.Characteristics));
      }

      Console.WriteLine("            },");

      static string GetCharacteristicsStr(IMAGE_SCN characteristics)
      {
        // Note: the alignment is a value in the IMAGE_SCN_ALIGN_MASK bits, the other bits are the flags
        var names = Enum.GetNames(typeof(IMAGE_SCN));
        var values = (IMAGE_SCN[])Enum.GetValues(typeof(IMAGE_SCN));

        var builder = new StringBuilder();

        void Append(string str)
        {
          if (builder.Length > 0)
            builder.Append(" | ");
          builder.Append(str);
        }

        var align = characteristics & IMAGE_SCN.IMAGE_SCN_ALIGN_MASK;
        if (align != 0)
        {
          var index = Array.IndexOf(values, align);
          Append(index >= 0 && align != IMAGE_SCN.IMAGE_SCN_ALIGN_MASK ? "IMAGE_SCN." + names[index] : $"(IMAGE_SCN)0x{(uint)align:X8}");
        }

        var rest = (uint)(characteristics & ~IMAGE_SCN.IMAGE_SCN_ALIGN_MASK);
        for (var n = 0; n < names.Length; ++n)
        {
          var value = (uint)values[n];
          if (value == 0 || (value & (value - 1)) != 0 || (value & (uint)IMAGE_SCN.IMAGE_SCN_ALIGN_MASK) != 0 || (rest & value) != value)
            continue;
          rest &= ~value;
          Append("IMAGE_SCN." + names[n]);
        }

        if (rest != 0)
          Append($"(IMAGE_SCN)0x{rest:X8}");
        return builder.Length == 0 ? "0" : builder.ToString();
      }
    }

    private static void GenerateExportInfos(ICollection<PeUtil.Export> exports)
    {
      if (exports.Count == 0)
      {
        Console.WriteLine("          new Export[] {},");
        return;
      }

      Console.WriteLine("          new Export[]");
      Console.WriteLine("            {");

      var maxHashLength = exports.Select(x => x.CreateStream == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxOrdinalLength = exports.Select(x => x.Ordinal.ToString().Length).DefaultIfEmpty(0).Max();
      var maxVirtualAddressLength = exports.Select(x => ("0x" + x.VirtualAddress.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxNameLength = exports.Select(x => GetStr(x.Name).Length).DefaultIfEmpty(0).Max();
      foreach (var export in exports)
      {
        var hash = export.CreateStream == null ? null : CalculateStreamHash(() => export.CreateStream());

        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          export.Ordinal.ToString().PadLeft(maxOrdinalLength),
          ("0x" + export.VirtualAddress.ToString("X")).PadLeft(maxVirtualAddressLength),
          GetStr(export.Name).PadRight(maxNameLength),
          GetStr(export.Forwarder));
      }

      Console.WriteLine("            },");

      static string GetStr(string? str) => str == null ? @null : '"' + str + '"';
    }

    private static void GenerateSymbolInfos(ICollection<PeUtil.Symbol> symbols)
    {
      if (symbols.Count == 0)
      {
        Console.WriteLine("          new Symbol[] {},");
        return;
      }

      Console.WriteLine("          new Symbol[]");
      Console.WriteLine("            {");

      var maxHashLength = symbols.Select(x => x.CreateStream == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxValueLength = symbols.Select(x => ("0x" + x.Value.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxSectionNumberLength = symbols.Select(x => GetSectionNumberStr(x.SectionNumber).Length).DefaultIfEmpty(0).Max();
      var maxNameLength = symbols.Select(x => x.Name.Length).DefaultIfEmpty(0).Max();
      var maxBaseTypeLength = symbols.Select(x => GetEnumStr(x.BaseType).Length).DefaultIfEmpty(0).Max();
      var maxDerivedTypeLength = symbols.Select(x => GetEnumStr(x.DerivedType).Length).DefaultIfEmpty(0).Max();
      var maxStorageClassLength = symbols.Select(x => GetEnumStr(x.StorageClass).Length).DefaultIfEmpty(0).Max();
      foreach (var symbol in symbols)
      {
        var hash = symbol.CreateStream == null ? null : CalculateStreamHash(() => symbol.CreateStream());

        var sectionNumberStr = GetSectionNumberStr(symbol.SectionNumber);
        Console.WriteLine(
          "              new({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          ("0x" + symbol.Value.ToString("X")).PadLeft(maxValueLength),
          sectionNumberStr.StartsWith("IMAGE_SYM.") ? sectionNumberStr.PadRight(maxSectionNumberLength) : sectionNumberStr.PadLeft(maxSectionNumberLength),
          ('"' + symbol.Name + '"').PadRight(maxNameLength + 2),
          GetEnumStr(symbol.BaseType).PadRight(maxBaseTypeLength),
          GetEnumStr(symbol.DerivedType).PadRight(maxDerivedTypeLength),
          GetEnumStr(symbol.StorageClass).PadRight(maxStorageClassLength),
          symbol.NumberOfAuxSymbols);
      }

      Console.WriteLine("            },");

      static string GetSectionNumberStr(ushort sectionNumber)
      {
        var name = (IMAGE_SYM)sectionNumber == IMAGE_SYM.IMAGE_SYM_UNDEFINED || (IMAGE_SYM)sectionNumber > IMAGE_SYM.IMAGE_SYM_SECTION_MAX ? Enum.GetName(typeof(IMAGE_SYM), (IMAGE_SYM)sectionNumber) : null;
        return name != null ? "IMAGE_SYM." + name : sectionNumber.ToString();
      }

      static string GetEnumStr<T>(T value) where T : struct, Enum
      {
        var name = Enum.GetName(typeof(T), value);
        return name != null ? typeof(T).Name + "." + name : $"({typeof(T).Name})0x{Convert.ToUInt64(value):X}";
      }
    }
  }
}
