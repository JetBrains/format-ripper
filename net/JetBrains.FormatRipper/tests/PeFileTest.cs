using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
      Section[] expectedSections,
      Export[] expectedExports,
      Symbol[] expectedSymbols,
      Dictionary<string, string> expectedExportStrings,
      Dictionary<string, string> expectedSymbolStrings) => new object?[]
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
          expectedExportCount,
          expectedSymbolCount,
          expectedSections,
          expectedExports,
          expectedSymbols,
          expectedExportStrings,
          expectedSymbolStrings
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
      int expectedExportCount,
      int expectedSymbolCount,
      Section[] expectedSections,
      Export[] expectedExports,
      Symbol[] expectedSymbols,
      Dictionary<string, string> expectedExportStrings,
      Dictionary<string, string> expectedSymbolStrings) => new object?[]
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
          expectedExportCount,
          expectedSymbolCount,
          expectedSections,
          expectedExports,
          expectedSymbols,
          expectedExportStrings,
          expectedSymbolStrings
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
      int expectedExportCount,
      int expectedSymbolCount,
      Section[] expectedSections,
      Export[] expectedExports,
      Symbol[] expectedSymbols,
      Dictionary<string, string> expectedExportStrings,
      Dictionary<string, string> expectedSymbolStrings)
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

          var exports = new List<PeUtil.Export>(expectedExportCount);
          Assert.IsTrue(PeUtil.GetExports(file, export =>
            {
              exports.Add(export);
              return true;
            }));
          Assert.AreEqual(expectedExportCount, exports.Count, "Unexpected export count");

          var verifiedExports = SymbolUtil.SelectEdges(exports);
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

          SymbolUtil.AssertLookups(CheckExportLookups(file, exports, SymbolUtil.MakeLookups(exports, x => x.Name, IsNamed, _ => true), exports.Count <= SymbolUtil.MaxLinearLookupSymbolCount));
          SymbolUtil.AssertStrings(expectedExportStrings, name => PeUtil.TryGetExport(file, name, out var export) ? export.CreateStream : null, PeUtil.ReadStringZ);

          var symbols = new List<PeUtil.Symbol>(expectedSymbolCount);
          Assert.IsTrue(PeUtil.GetSymbols(file, symbol =>
            {
              symbols.Add(symbol);
              return true;
            }));
          Assert.AreEqual(expectedSymbolCount, symbols.Count, "Unexpected symbol count");

          var verifiedSymbols = SymbolUtil.SelectEdges(symbols);
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

          SymbolUtil.AssertLookups(CheckSymbolLookups(file, symbols, SymbolUtil.MakeLookups(symbols, x => x.Name, IsExternal, IsDefined)));
          SymbolUtil.AssertStrings(expectedSymbolStrings, name => PeUtil.TryGetSymbol(file, name, out var symbol) ? symbol.CreateStream : null, PeUtil.ReadStringZ);
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

    private static string CalculateStreamHash(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA256.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }
  }
}
