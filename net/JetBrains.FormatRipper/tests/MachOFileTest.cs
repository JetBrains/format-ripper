using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using JetBrains.FormatRipper.MachO;
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

    public sealed class Section
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
      public readonly DataSection[]? DataSections;
      public readonly Symbol[]? Symbols;

      internal Section(
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
        DataSection[]? dataSections,
        Symbol[]? symbols)
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
      }
    }

    private static object?[] MakeSource(
      string filename,
      Section section) => new object?[]
      {
        false,
        filename,
        null,
        null,
        new[] { section }
      };

    private static object?[] MakeSource(
      string filename,
      MachOFile.Endian fatEndian,
      params Section[] sections) => new object?[]
      {
        false,
        filename,
        fatEndian,
        null,
        sections
      };

    private static object?[] MakeSource(
      string filename,
      string? expectedUnityScriptingBackend,
      MachOFile.Endian fatEndian,
      params Section[] sections) => new object?[]
      {
        false,
        filename,
        fatEndian,
        expectedUnityScriptingBackend,
        sections
      };

    private static object?[] MakeOptionalSource(
      string filename,
      string? expectedUnityScriptingBackend,
      Section section) => new object?[]
      {
        true,
        filename,
        null,
        expectedUnityScriptingBackend,
        new[] { section }
      };

    private static object?[] MakeOptionalSource(
      string filename,
      string? expectedUnityScriptingBackend,
      MachOFile.Endian fatEndian,
      params Section[] sections) => new object?[]
      {
        true,
        filename,
        fatEndian,
        expectedUnityScriptingBackend,
        sections
      };

    [TestCaseSource(typeof(MachOFileTest), nameof(Sources))]
    [Test]
    public void Test(
      bool canIgnoreMissingResource,
      string resourceName,
      MachOFile.Endian? expectedFatEndian,
      string? expectedUnityScriptingBackend,
      Section[] expectedSections)
    {
      TestDataUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.IsTrue(MachOFile.Is(stream));
          var file = MachOFile.Parse(stream);

          var sections = file.Sections;
          Assert.AreEqual(expectedFatEndian, file.FatEndian);
          Assert.AreEqual(expectedSections.Length, sections.Length);

          string? unityScriptingBackend = null;
          for (var n = 0; n < sections.Length; n++)
          {
            var section = sections[n];
            var expectedSection = expectedSections[n];

            Assert.AreEqual(expectedSection.Hash, CalculateStreamHash384(() => section.CreateStream()));
            Assert.AreEqual(expectedSection.Endian, section.Endian);
            Assert.AreEqual(expectedSection.CpuType, section.CpuType);
            Assert.AreEqual(expectedSection.CpuSubType, section.CpuSubType);
            Assert.AreEqual(expectedSection.MhFileType, section.MhFileType);
            Assert.AreEqual(expectedSection.MhFlags, section.MhFlags);

            var expectedCommands = expectedSection.Commands;
            var commands = section.Commands;
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

            var hasSignedBlob = (expectedSection.Options & Options.HasSignedBlob) == Options.HasSignedBlob;
            var hasCmsBlob = (expectedSection.Options & Options.HasCmsBlob) == Options.HasCmsBlob;
            var hasEntitlements = (expectedSection.Options & Options.HasEntitlements) == Options.HasEntitlements;
            var hasEntitlementsDer = (expectedSection.Options & Options.HasEntitlementsDer) == Options.HasEntitlementsDer;

            var loadCommandsInfo = MachOUtil.ReadLoadCommands(section, MachOFile.Mode.SignatureData);
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
              Assert.AreEqual(expectedSection.CodeDirectoryBlobHash, HexUtil.ConvertToHexString(hash));
            }
            else
            {
              Assert.IsFalse(hasCmsBlob);
              Assert.IsNull(expectedSection.CodeDirectoryBlobHash);
            }

            if (cmsBlob != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(cmsBlob);
              Assert.AreEqual(expectedSection.CmsDataHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.IsNull(expectedSection.CmsDataHash);

            if (entitlements != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlements);

              Assert.AreEqual(expectedSection.EntitlementsHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedSection.EntitlementsHash);

            if (entitlementsDer != null)
            {
              byte[] hash;
              using (var hashAlgorithm = SHA384.Create())
                hash = hashAlgorithm.ComputeHash(entitlementsDer);

              Assert.AreEqual(expectedSection.EntitlementsDerHash, HexUtil.ConvertToHexString(hash));
            }
            else
              Assert.Null(expectedSection.EntitlementsDerHash);

            var dataSections = MachOUtil.ReadDataSections(section);
            if (expectedSection.DataSections != null)
            {
              var expectedDataSections = expectedSection.DataSections;
              Assert.AreEqual(expectedDataSections.Length, dataSections.Count, $"Unexpected data section count in the section {n}");
              for (var k = 0; k < expectedDataSections.Length; ++k)
                AssertDataSection(expectedDataSections[k], dataSections[k]);
            }
            else
              GenerateDataSectionInfos(dataSections);

            var symbols = new List<MachOUtil.Symbol>(expectedSection.SymbolCount);
            Assert.IsTrue(MachOUtil.GetSymbols(section, dataSections, symbol =>
              {
                symbols.Add(symbol);
                return true;
              }));
            Assert.AreEqual(expectedSection.SymbolCount, symbols.Count, $"Unexpected symbol count in the section {n}");

            var verifiedSymbols = SymbolUtil.SelectEdges(symbols);
            if (expectedSection.Symbols != null)
            {
              var expectedSectionSymbols = expectedSection.Symbols;
              Assert.AreEqual(expectedSectionSymbols.Length, verifiedSymbols.Length);
              for (var k = 0; k < expectedSectionSymbols.Length; ++k)
              {
                var expectedSymbol = expectedSectionSymbols[k];
                var symbol = verifiedSymbols[k];

                Assert.AreEqual(expectedSymbol.Name, symbol.Name);
                Assert.AreEqual(expectedSymbol.Value, symbol.Value, $"Expected 0x{expectedSymbol.Value:X}, but was 0x{symbol.Value:X}");
                Assert.AreEqual(expectedSymbol.SectionIndex, symbol.SectionIndex);
                Assert.AreEqual(expectedSymbol.Type, symbol.Type, $"Expected 0x{(byte)expectedSymbol.Type:X}, but was 0x{(byte)symbol.Type:X}");
                Assert.AreEqual(expectedSymbol.Desc, symbol.Description, $"Expected 0x{(ushort)expectedSymbol.Desc:X}, but was 0x{(ushort)symbol.Description:X}");

                var hash = symbol.CreateStream == null ? null : CalculateStreamHash(() => symbol.CreateStream());
                Assert.AreEqual(expectedSymbol.Hash, hash);
              }
            }
            else
              GenerateSymbolInfos(verifiedSymbols);

            if (unityScriptingBackend == null)
              foreach (var symbol in symbols)
                if (symbol.Name == UnityUtil.UNITY_SCRIPTING_BACKEND_MACHO_PE_SYMBOL &&
                    (symbol.Type & (NT.N_STAB | NT.N_TYPE | NT.N_EXT)) == (NT.N_SECT | NT.N_EXT))
                {
                  using var dataStream = symbol.CreateStream!();
                  unityScriptingBackend = MachOUtil.ReadStringZ(dataStream);
                  break;
                }
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

    [TestCase("libclang_rt.cc_kext.a")]
    [TestCase("libclang_rt.soft_static.a")]
    [Test]
    public void ErrorTest(string resourceName)
    {
      TestDataUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Assert.IsFalse(MachOFile.Is(stream));
          Assert.That(() => MachOFile.Parse(stream), Throws.Exception);
        });
    }

    private const int Sha256HashStringLength = 2 * 256 / 8;
    private const string @null = "null";

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

    private static void GenerateDataSectionInfos(ICollection<MachOUtil.DataSection> dataSectionItems)
    {
      Console.WriteLine("            new DataSection[]");
      Console.WriteLine("              {");

      var maxHashLength = dataSectionItems.Select(x => x.CreateSection == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxAddressLength = dataSectionItems.Select(x => ("0x" + x.Address.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxSizeLength = dataSectionItems.Select(x => x.Size.ToString().Length).DefaultIfEmpty(0).Max();
      var maxSectionNameLength = dataSectionItems.Select(x => x.SectionName.Length).DefaultIfEmpty(0).Max();
      var maxSegmentNameLength = dataSectionItems.Select(x => x.SegmentName.Length).DefaultIfEmpty(0).Max();
      foreach (var dataSectionItem in dataSectionItems)
        Console.WriteLine("                {0},", GetStr(dataSectionItem, maxHashLength, maxAddressLength, maxSizeLength, maxSectionNameLength, maxSegmentNameLength));

      Console.WriteLine("              },");

      static string GetStr(MachOUtil.DataSection dataSectionItem, int maxHashLength, int maxAddressLength, int maxSizeLength, int maxSectionNameLength, int maxSegmentNameLength) => string.Format(
        "new({0}, {1}, {2}, {3}, {4}, {5})",
        (dataSectionItem.CreateSection == null ? @null : '"' + CalculateStreamHash(() => dataSectionItem.CreateSection()) + '"').PadRight(maxHashLength),
        ("0x" + dataSectionItem.Address.ToString("X")).PadLeft(maxAddressLength),
        dataSectionItem.Size.ToString().PadLeft(maxSizeLength),
        ('"' + dataSectionItem.SectionName + '"').PadRight(maxSectionNameLength + 2),
        ('"' + dataSectionItem.SegmentName + '"').PadRight(maxSegmentNameLength + 2),
        GetFlagsStr(dataSectionItem.Flags));

      static string GetFlagsStr(SEC flags)
      {
        // Note: the section type is a value in the low byte, the section attributes are the flags in the high bytes
        var names = Enum.GetNames(typeof(SEC));
        var values = (SEC[])Enum.GetValues(typeof(SEC));

        var type = flags & SEC.SECTION_TYPE;
        var builder = new StringBuilder(GetTypeStr());
        var rest = (uint)(flags & SEC.SECTION_ATTRIBUTES);
        for (var n = names.Length - 1; n >= 0; --n)
        {
          var value = (uint)values[n];
          if (value == 0 || (rest & value) != value || IsMask(names[n]))
            continue;
          rest &= ~value;
          builder.Append(" | SEC." + names[n]);
        }

        if (rest != 0)
          builder.Append($" | (SEC)0x{rest:X8}");
        return builder.ToString();

        string GetTypeStr()
        {
          for (var n = 0; n < names.Length; ++n)
            if (values[n] == type && !IsMask(names[n]))
              return "SEC." + names[n];
          return $"(SEC)0x{(uint)type:X2}";
        }

        static bool IsMask(string name) => name is nameof(SEC.SECTION_ATTRIBUTES) or nameof(SEC.SECTION_ATTRIBUTES_USR) or nameof(SEC.SECTION_ATTRIBUTES_SYS) or nameof(SEC.SECTION_TYPE);
      }
    }

    private static void GenerateSymbolInfos(ICollection<MachOUtil.Symbol> symbolItems)
    {
      Console.WriteLine("            new Symbol[]");
      Console.WriteLine("              {");

      var maxHashLength = symbolItems.Select(x => x.CreateStream == null ? @null.Length : Sha256HashStringLength + 2).DefaultIfEmpty(0).Max();
      var maxNameLength = symbolItems.Select(x => x.Name.Length).DefaultIfEmpty(0).Max();
      var maxValueLength = symbolItems.Select(x => ("0x" + x.Value.ToString("X")).Length).DefaultIfEmpty(0).Max();
      var maxSectionIndexLength = symbolItems.Select(x => x.SectionIndex.ToString().Length).DefaultIfEmpty(0).Max();
      var maxTypeLength = symbolItems.Select(x => GetTypeStr(x.Type).Length).DefaultIfEmpty(0).Max();
      foreach (var symbolItem in symbolItems)
      {
        var hash = symbolItem.CreateStream == null ? null : CalculateStreamHash(() => symbolItem.CreateStream());

        Console.WriteLine(
          "                new({0}, {1}, {2}, {3}, {4}, {5}),",
          (hash == null ? @null : '"' + hash + '"').PadRight(maxHashLength),
          ("0x" + symbolItem.Value.ToString("X")).PadLeft(maxValueLength),
          symbolItem.SectionIndex.ToString().PadLeft(maxSectionIndexLength),
          ('"' + symbolItem.Name + '"').PadRight(maxNameLength + 2),
          GetTypeStr(symbolItem.Type).PadRight(maxTypeLength),
          GetDescStr(symbolItem.Type, symbolItem.Value, symbolItem.Description));
      }

      Console.WriteLine("              },");

      static string GetTypeStr(NT type)
      {
        if ((type & NT.N_STAB) != 0)
          return GetStr(type);

        var builder = new StringBuilder();
        if ((type & NT.N_PEXT) != 0)
          builder.Append("NT.N_PEXT | ");
        builder.Append(GetStr(type & NT.N_TYPE));
        if ((type & NT.N_EXT) != 0)
          builder.Append(" | NT.N_EXT");
        return builder.ToString();
      }

      static string GetStr(NT type)
      {
        // Note: N_SECT aliases the N_TYPE mask and N_RBRAC aliases the N_STAB mask, so the masks are skipped here
        var names = Enum.GetNames(typeof(NT));
        var values = (NT[])Enum.GetValues(typeof(NT));
        for (var n = 0; n < names.Length; ++n)
          if (values[n] == type && names[n] is not (nameof(NT.N_STAB) or nameof(NT.N_PEXT) or nameof(NT.N_TYPE) or nameof(NT.N_EXT)))
            return "NT." + names[n];
        return $"(NT)0x{(byte)type:X2}";
      }

      static string GetDescStr(NT type, ulong value, ND desc)
      {
        // Note: the n_desc field of a stab is a plain number, not a set of flags
        if ((type & NT.N_STAB) != 0)
          return desc == 0 ? "0" : $"(ND)0x{(ushort)desc:X4}";

        // Note: a common symbol is an undefined external one with the non-zero value which holds the symbol size
        var isCommon = (type & (NT.N_TYPE | NT.N_EXT)) == (NT.N_UNDF | NT.N_EXT) && value != 0;
        var isUndefined = (type & NT.N_TYPE) is NT.N_UNDF or NT.N_PBUD;
        var rest = (ushort)desc;
        var builder = new StringBuilder();

        void Append(string str)
        {
          if (builder.Length > 0)
            builder.Append(" | ");
          builder.Append(str);
        }

        void AppendFlag(ND flag, string name)
        {
          if ((rest & (ushort)flag) == 0)
            return;
          rest &= (ushort)~(ushort)flag;
          Append("ND." + name);
        }

        string? setter = null;
        byte field = 0;

        if (isCommon)
        {
          field = NDUtil.GetCommAlign(desc);
          rest &= unchecked((ushort)~(ushort)ND.COMM_ALIGN);
          if (field != 0)
            setter = nameof(NDUtil.SetCommAlign);
        }
        else if (isUndefined)
        {
          field = NDUtil.GetLibraryOrdinal(desc);
          rest &= unchecked((ushort)~(ushort)ND.LIBRARY_ORDINAL);
          switch ((ND)(field << 8))
          {
          case ND.SELF_LIBRARY_ORDINAL: break;
          case ND.MAX_LIBRARY_ORDINAL: Append("ND." + nameof(ND.MAX_LIBRARY_ORDINAL)); break;
          case ND.DYNAMIC_LOOKUP_ORDINAL: Append("ND." + nameof(ND.DYNAMIC_LOOKUP_ORDINAL)); break;
          case ND.EXECUTABLE_ORDINAL: Append("ND." + nameof(ND.EXECUTABLE_ORDINAL)); break;
          default: setter = nameof(NDUtil.SetLibraryOrdinal); break;
          }
        }
        else
        {
          AppendFlag(ND.N_COLD_FUNC, nameof(ND.N_COLD_FUNC));
          AppendFlag(ND.N_ALT_ENTRY, nameof(ND.N_ALT_ENTRY));
          AppendFlag(ND.N_SYMBOL_RESOLVER, nameof(ND.N_SYMBOL_RESOLVER));
        }

        AppendFlag(ND.N_WEAK_DEF, isUndefined ? nameof(ND.N_REF_TO_WEAK) : nameof(ND.N_WEAK_DEF));
        AppendFlag(ND.N_WEAK_REF, nameof(ND.N_WEAK_REF));
        AppendFlag(ND.N_NO_DEAD_STRIP, nameof(ND.N_NO_DEAD_STRIP));
        AppendFlag(ND.REFERENCED_DYNAMICALLY, nameof(ND.REFERENCED_DYNAMICALLY));
        AppendFlag(ND.N_ARM_THUMB_DEF, nameof(ND.N_ARM_THUMB_DEF));

        var referenceName = (rest & (ushort)ND.REFERENCE_TYPE) switch
          {
            (ushort)ND.REFERENCE_FLAG_UNDEFINED_LAZY => nameof(ND.REFERENCE_FLAG_UNDEFINED_LAZY),
            (ushort)ND.REFERENCE_FLAG_DEFINED => nameof(ND.REFERENCE_FLAG_DEFINED),
            (ushort)ND.REFERENCE_FLAG_PRIVATE_DEFINED => nameof(ND.REFERENCE_FLAG_PRIVATE_DEFINED),
            (ushort)ND.REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY => nameof(ND.REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY),
            (ushort)ND.REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY => nameof(ND.REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY),
            _ => null
          };
        if (referenceName != null)
        {
          rest &= unchecked((ushort)~(ushort)ND.REFERENCE_TYPE);
          Append("ND." + referenceName);
        }

        if (rest != 0)
          Append($"(ND)0x{rest:X4}");

        if (setter != null)
          return builder.Length == 0
            ? $"{nameof(NDUtil)}.{setter}({field})"
            : $"{nameof(NDUtil)}.{setter}({field}, {builder})";

        return builder.Length == 0 ? "0" : builder.ToString();
      }
    }
  }
}