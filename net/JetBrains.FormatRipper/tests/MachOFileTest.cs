using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.MachO.Impl;
using JetBrains.Tests;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed partial class MachOFileTest
  {
    [Flags]
    public enum Options
    {
      HasCmsBlob         = 0x1,
      HasSignedBlob      = 0x2,
      HasEntitlements    = 0x4,
      HasEntitlementsDer = 0x8,
    }

    public sealed class Symbol
    {
      public readonly string? Hash;
      public readonly ulong Value;
      public readonly byte SectionIndex;
      public readonly string Name;
      public readonly NT Type;
      public readonly ND Desc;

      internal Symbol(string? hash, ulong value, byte sectionIndex, string name, NT type, ND desc)
      {
        Hash = hash;
        Value = value;
        SectionIndex = sectionIndex;
        Name = name;
        Type = type;
        Desc = desc;
      }

      public override string ToString() => $"{Hash}, 0x{Value:X}, {SectionIndex}, \"{Name}\", 0x{(byte)Type:X}, 0x{(ushort)Desc:X}";
    }

    public sealed class Command
    {
      public readonly string Hash;
      public readonly uint Size;
      public readonly LC Type;

      internal Command(string hash, uint size, LC type)
      {
        Hash = hash;
        Size = size;
        Type = type;
      }
    }

    public sealed class DataSection
    {
      public readonly string? Hash;
      public readonly ulong Address;
      public readonly ulong Size;
      public readonly string SectionName;
      public readonly string SegmentName;
      public readonly SEC Flags;

      internal DataSection(string? hash, ulong address, ulong size, string sectionName, string segmentName, SEC flags)
      {
        Hash = hash;
        Address = address;
        Size = size;
        SectionName = sectionName;
        SegmentName = segmentName;
        Flags = flags;
      }

      public override string ToString() => $"{Hash}, 0x{Address:X}, {Size}, \"{SectionName}\", \"{SegmentName}\", 0x{(uint)Flags:X}";
    }

    public sealed class Image
    {
      public readonly string Hash;
      public readonly MachOFile.Endian Endian;
      public readonly CPU_TYPE CpuType;
      public readonly CPU_SUBTYPE CpuSubType;
      public readonly MH_FileType MhFileType;
      public readonly MH_Flags MhFlags;
      public readonly Options Options;
      public readonly string? CodeDirectoryBlobHash;
      public readonly string? CmsDataHash;
      public readonly string? EntitlementsHash;
      public readonly string? EntitlementsDerHash;
      public readonly int SymbolCount;
      public readonly Command[] Commands;
      public readonly DataSection[] DataSections;
      public readonly Symbol[] Symbols;
      public readonly Dictionary<string, string> SymbolStrings;

      internal Image(
        string hash,
        MachOFile.Endian endian,
        CPU_TYPE cpuType,
        CPU_SUBTYPE cpuSubType,
        MH_FileType mhFileType,
        MH_Flags mhFlags,
        Options options,
        string? codeDirectoryBlobHash,
        string? cmsDataHash,
        string? entitlementsHash,
        string? entitlementsDerHash,
        int symbolCount,
        Command[] commands,
        DataSection[] dataSections,
        Symbol[] symbols,
        Dictionary<string, string> symbolStrings)
      {
        Hash = hash;
        Endian = endian;
        CpuType = cpuType;
        CpuSubType = cpuSubType;
        MhFileType = mhFileType;
        MhFlags = mhFlags;
        Options = options;
        CodeDirectoryBlobHash = codeDirectoryBlobHash;
        CmsDataHash = cmsDataHash;
        EntitlementsHash = entitlementsHash;
        EntitlementsDerHash = entitlementsDerHash;
        SymbolCount = symbolCount;
        Commands = commands;
        DataSections = dataSections;
        Symbols = symbols;
        SymbolStrings = symbolStrings;
      }
    }

    private static object?[] MakeSource(
      string filename,
      Image image) => new object?[]
      {
        false,
        filename,
        null,
        new[] { image }
      };

    private static object?[] MakeSource(
      string filename,
      MachOFile.Endian fatEndian,
      params Image[] images) => new object?[]
      {
        false,
        filename,
        fatEndian,
        images
      };

    private static object?[] MakeOptionalSource(
      string filename,
      Image image) => new object?[]
      {
        true,
        filename,
        null,
        new[] { image }
      };

    private static object?[] MakeOptionalSource(
      string filename,
      MachOFile.Endian fatEndian,
      params Image[] images) => new object?[]
      {
        true,
        filename,
        fatEndian,
        images
      };

    [TestCaseSource(typeof(MachOFileTest), nameof(Sources))]
    [Test]
    public void Test(
      bool canIgnoreMissingResource,
      string resourceName,
      MachOFile.Endian? expectedFatEndian,
      Image[] expectedImages)
    {
      TestDataUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          var file = MachOFile.Parse(stream);

          var images = file.Images;
          Assert.AreEqual(expectedFatEndian, file.FatEndian);
          Assert.AreEqual(expectedImages.Length, images.Length);

          for (var n = 0; n < images.Length; n++)
          {
            var image = images[n];
            var expectedImage = expectedImages[n];

            Assert.AreEqual(expectedImage.Hash, CalculateStreamHash384(() => image.CreateStream()));
            Assert.AreEqual(expectedImage.Endian, image.Endian);
            Assert.AreEqual(ReadMagic(image) is MH.MH_MAGIC_64 or MH.MH_CIGAM_64, image.Is64);
            Assert.AreEqual(expectedImage.CpuType, image.CpuType);
            Assert.AreEqual(expectedImage.CpuSubType, image.CpuSubType);
            Assert.AreEqual(expectedImage.MhFileType, image.MhFileType);
            Assert.AreEqual(expectedImage.MhFlags, image.MhFlags);

            var expectedCommands = expectedImage.Commands;
            var commands = image.Commands;
            Assert.AreEqual(expectedCommands.Length, commands.Length);
            for (var k = 0; k < expectedCommands.Length; k++)
            {
              var expectedCommand = expectedCommands[k];
              var command = commands[k];

              Assert.AreEqual(expectedCommand.Type, command.Type);
              Assert.AreEqual(expectedCommand.Size, command.Size);

              var hash = CalculateStreamHash(() => command.CreateStream());
              Assert.AreEqual(expectedCommand.Hash, hash);
            }

            var hasSignedBlob = (expectedImage.Options & Options.HasSignedBlob) == Options.HasSignedBlob;
            var hasCmsBlob = (expectedImage.Options & Options.HasCmsBlob) == Options.HasCmsBlob;
            var hasEntitlements = (expectedImage.Options & Options.HasEntitlements) == Options.HasEntitlements;
            var hasEntitlementsDer = (expectedImage.Options & Options.HasEntitlementsDer) == Options.HasEntitlementsDer;

            var loadCommandsInfo = MachOUtil.ReadLoadCommands(image, MachOUtil.Mode.SignatureData);
            var signedBlob = loadCommandsInfo.SignatureData.SignedBlob;
            var cmsBlob = loadCommandsInfo.SignatureData.CmsBlob;
            var entitlements = loadCommandsInfo.Entitlements;
            var entitlementsDer = loadCommandsInfo.EntitlementsDer;

            Assert.AreEqual(hasSignedBlob, loadCommandsInfo.HasSignature);
            Assert.AreEqual(hasSignedBlob, signedBlob != null);
            Assert.AreEqual(hasCmsBlob, cmsBlob != null);
            Assert.AreEqual(hasEntitlements, entitlements != null);
            Assert.AreEqual(hasEntitlementsDer, entitlementsDer != null);

            if (signedBlob != null)
            {
              Assert.AreEqual((byte)0xFA, signedBlob[0]);
              Assert.AreEqual((byte)0xDE, signedBlob[1]);
              Assert.AreEqual((byte)0x0C, signedBlob[2]);
              Assert.AreEqual((byte)0x02, signedBlob[3]);

              var length = checked((int)(
                (uint)signedBlob[4] << 24 |
                (uint)signedBlob[5] << 16 |
                (uint)signedBlob[6] << 8 |
                (uint)signedBlob[7] << 0));
              Assert.AreEqual(length, signedBlob.Length);

              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(signedBlob);
              Assert.AreEqual(expectedImage.CodeDirectoryBlobHash, HexUtil.ConvertToHexString(hash));
            }
            else
            {
              Assert.IsFalse(hasCmsBlob);
              Assert.IsNull(expectedImage.CodeDirectoryBlobHash);
            }

            if (cmsBlob != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(cmsBlob);
              Assert.AreEqual(expectedImage.CmsDataHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.IsNull(expectedImage.CmsDataHash);

            if (entitlements != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlements);

              Assert.AreEqual(expectedImage.EntitlementsHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedImage.EntitlementsHash);

            if (entitlementsDer != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlementsDer);

              Assert.AreEqual(expectedImage.EntitlementsDerHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedImage.EntitlementsDerHash);

            var dataSections = MachOUtil.ReadDataSections(image);
            var expectedDataSections = expectedImage.DataSections;
            Assert.AreEqual(expectedDataSections.Length, dataSections.Count, $"Unexpected data image count in the image {n}");
            for (var k = 0; k < expectedDataSections.Length; ++k)
              AssertDataSection(expectedDataSections[k], dataSections[k]);

            var symbols = new List<MachOUtil.Symbol>(expectedImage.SymbolCount);
            Assert.IsTrue(MachOUtil.GetSymbols(image, dataSections, symbol =>
              {
                symbols.Add(symbol);
                return true;
              }));
            Assert.AreEqual(expectedImage.SymbolCount, symbols.Count, $"Unexpected symbol count in the image {n}");

            var verifiedSymbols = SymbolUtil.SelectEdges(symbols);
            var expectedImageSymbols = expectedImage.Symbols;
            Assert.AreEqual(expectedImageSymbols.Length, verifiedSymbols.Length);
            for (var k = 0; k < expectedImageSymbols.Length; ++k)
            {
              var expectedSymbol = expectedImageSymbols[k];
              var symbol = verifiedSymbols[k];

              Assert.AreEqual(expectedSymbol.Name, symbol.Name);
              Assert.AreEqual(expectedSymbol.Value, symbol.Value, $"Expected 0x{expectedSymbol.Value:X}, but was 0x{symbol.Value:X}");
              Assert.AreEqual(expectedSymbol.SectionIndex, symbol.SectionIndex);
              Assert.AreEqual(expectedSymbol.Type, symbol.Type, $"Expected 0x{(byte)expectedSymbol.Type:X}, but was 0x{(byte)symbol.Type:X}");
              Assert.AreEqual(expectedSymbol.Desc, symbol.Description, $"Expected 0x{(ushort)expectedSymbol.Desc:X}, but was 0x{(ushort)symbol.Description:X}");

              var hash = symbol.CreateStream == null ? null : CalculateStreamHash(() => symbol.CreateStream());
              Assert.AreEqual(expectedSymbol.Hash, hash);
            }

            SymbolUtil.AssertLookups(CheckLookups(image, dataSections, symbols, SymbolUtil.MakeLookups(symbols, x => x.Name, IsExternal, IsDefined), symbols.Count <= SymbolUtil.MaxLinearLookupSymbolCount));
            SymbolUtil.AssertStrings(expectedImage.SymbolStrings, name => MachOUtil.TryGetSymbol(image, dataSections, name, out var symbol) ? symbol.CreateStream : null, MachOUtil.ReadStringZ);
          }
        }, str =>
        {
          if (canIgnoreMissingResource)
            Assert.Ignore(str);
        });
    }

    [TestCase("libclang_rt.cc_kext.a")]
    [TestCase("libclang_rt.soft_static.a")]
    [Test]
    public void ErrorTest(string resourceName)
    {
      TestDataUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.That(() => MachOFile.Parse(stream), Throws.Exception);
        });
    }

    private static bool IsExternal(MachOUtil.Symbol symbol) => (symbol.Type & NT.N_STAB) == 0 && (symbol.Type & NT.N_EXT) != 0;

    private static bool IsDefined(MachOUtil.Symbol symbol) => (symbol.Type & NT.N_TYPE) is NT.N_ABS or NT.N_SECT or NT.N_INDR;

    private static List<string> CheckLookups(MachOFile.Image image, List<MachOUtil.DataSection> dataSections, IList<MachOUtil.Symbol> symbols, IEnumerable<Lookup> lookups, bool withLinear)
    {
      var errors = new List<string>();
      foreach (var lookup in lookups)
      {
        var name = lookup.Name;
        Check(nameof(MachOUtil.TryGetSymbol), MachOUtil.TryGetSymbol(image, dataSections, name, out var symbol), symbol);
        Check(nameof(MachOUtil.TryGetSymbolByDySymTab), MachOUtil.TryGetSymbolByDySymTab(image, dataSections, name, out symbol), symbol);
        if (withLinear)
          Check(nameof(MachOUtil.TryGetSymbolLinear), MachOUtil.TryGetSymbolLinear(image, dataSections, name, out symbol), symbol);

        void Check(string method, bool? isFound, MachOUtil.Symbol? found)
        {
          if (isFound != null && CheckLookup(lookup, symbols, method, isFound.Value, found) is { } error)
            errors.Add(error);
        }
      }

      return errors;
    }

    private static string? CheckLookup(Lookup lookup, IList<MachOUtil.Symbol> symbols, string method, bool isFound, MachOUtil.Symbol? symbol)
    {
      var expectedSymbol = lookup.Index == null ? null : symbols[lookup.Index.Value];
      if (isFound != (expectedSymbol != null) || isFound != (symbol != null))
        return $"{method}(\"{lookup.Name}\") returned {isFound}, but the expected symbol index is {lookup.Index?.ToString() ?? "null"}";
      if (expectedSymbol == null || symbol == null)
        return null;

      var error = $"{method}(\"{lookup.Name}\") returned \"{symbol.Name}\" at 0x{symbol.Value:X}, but the expected symbol {lookup.Index} is \"{expectedSymbol.Name}\" at 0x{expectedSymbol.Value:X}";
      if (symbol.Name != expectedSymbol.Name || symbol.Value != expectedSymbol.Value || symbol.SectionIndex != expectedSymbol.SectionIndex ||
          symbol.Type != expectedSymbol.Type || symbol.Description != expectedSymbol.Description ||
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

    private static string CalculateStreamHash384(Func<Stream> createStream)
    {
      using var itemStream = createStream();
      using var hashAlgorithm = SHA384.Create();
      return HexUtil.ConvertToHexString(hashAlgorithm.ComputeHash(itemStream));
    }

    private static MH ReadMagic(MachOFile.Image image)
    {
      using var stream = image.CreateStream();
      var magic = new byte[sizeof(uint)];
      Assert.AreEqual(magic.Length, stream.Read(magic, 0, magic.Length));
      return (MH)(magic[0] | (uint)magic[1] << 8 | (uint)magic[2] << 16 | (uint)magic[3] << 24);
    }

    private static void AssertDataSection(DataSection expectedDataSection, MachOUtil.DataSection dataSection)
    {
      Assert.AreEqual(expectedDataSection.Address, dataSection.Address, $"Expected 0x{expectedDataSection.Address:X}, but was 0x{dataSection.Address:X}");
      Assert.AreEqual(expectedDataSection.Size, dataSection.Size);
      Assert.AreEqual(expectedDataSection.SectionName, dataSection.SectionName);
      Assert.AreEqual(expectedDataSection.SegmentName, dataSection.SegmentName);
      Assert.AreEqual(expectedDataSection.Flags, dataSection.Flags, $"Expected 0x{(uint)expectedDataSection.Flags:X}, but was 0x{(uint)dataSection.Flags:X}");

      var hash = dataSection.CreateSection == null ? null : CalculateStreamHash(() => dataSection.CreateSection());
      Assert.AreEqual(expectedDataSection.Hash, hash);
    }
  }
}