using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class MachOFileTest
  {
    public class TestCase
    {
      public string resourceName { get; set; }
      public ResourceCategory resourceCategory { get; set; }
      public bool? isFatLittleEndian { get; set; }
      public SectionData[] sections { get; set; }
      public string description { get; set; }
    }

    public class SectionData
    {
      public bool isLittleEndian { get; set; }
      public CPU_TYPE cpuType { get; set; }
      public string cpuSubType { get; set; }
      public MH_FileType mhFileType { get; set; }
      public string options { get; set; }
      public string codeDirectoryBlobHash { get; set; }
      public string cmsDataHash { get; set; }
      public string orderedIncludeRanges { get; set; }
      public string entitlementsHash { get; set; }
      public string entitlementsDerHash { get; set; }
      public string description { get; set; }
    }

    private static IEnumerable<TestCaseData> LoadMachOTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"MachO_{testCase.resourceName.Replace(".", "_").Replace("-", "_")}")
          .SetDescription($"Test MachO file parsing for {testCase.resourceName} - {testCase.description}")
      );
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.MachOFileTestCases.json";

      return ResourceUtil.OpenRead(ResourceCategory.TestCases, "MachOFileTestCases.json", stream =>
      {
        using var reader = new JsonTextReader(new StreamReader(stream));
        var serializer = new JsonSerializer();
        serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
        var obj = serializer.Deserialize<List<TestCase>>(reader);
        if (obj == null)
          throw new InvalidOperationException($"Failed to deserialize test cases from {resourceName}");
        return obj;
      });
    }

    [Flags]
    public enum Options
    {
      HasCmsBlob         = 0x1,
      HasSignedBlob      = 0x2,
      HasEntitlements    = 0x4,
      HasEntitlementsDer = 0x8,
    }

    [TestCaseSource(nameof(LoadMachOTestCases))]
    [Test]
    public void TestMachOFile(TestCase testCase)
    {
      Console.WriteLine($"INFO: Testing MachO file: {testCase.resourceName}");

      var file = ResourceUtil.OpenRead(testCase.resourceCategory, testCase.resourceName, stream =>
        {
          Console.Error.WriteLine($"TRACE: Parsing MachO file: {testCase.resourceName}");
          Assert.IsTrue(MachOFile.Is(stream), $"File {testCase.resourceName} should be recognized as a MachO file");
          return MachOFile.Parse(stream, MachOFile.Mode.SignatureData | MachOFile.Mode.ComputeHashInfo);
        });

      Assert.AreEqual(testCase.isFatLittleEndian, file.IsFatLittleEndian, $"IsFatLittleEndian mismatch for {testCase.resourceName}");
      Assert.AreEqual(testCase.sections.Length, file.Sections.Length, $"Section count mismatch for {testCase.resourceName}");

      var fileSections = file.Sections;
      for (var n = 0; n < testCase.sections.Length; n++)
      {
        var sectionData = testCase.sections[n];
        var fileSection = fileSections[n];
        var indexMsg = $"Index {n} for {testCase.resourceName}";

        Console.Error.WriteLine($"TRACE: Testing section {n} of {testCase.resourceName}: {sectionData.description}");

        Assert.AreEqual(sectionData.isLittleEndian, fileSection.IsLittleEndian, indexMsg);

        Assert.AreEqual(sectionData.cpuType, fileSection.CpuType, indexMsg);

        // Handle complex CPU subtypes with bitwise OR
        CPU_SUBTYPE expectedCpuSubType = 0;
        if (!string.IsNullOrEmpty(sectionData.cpuSubType))
        {
          foreach (var subTypeName in sectionData.cpuSubType.Split('|').Select(s => s.Trim()))
          {
            var subType = (CPU_SUBTYPE)Enum.Parse(typeof(CPU_SUBTYPE), subTypeName);
            expectedCpuSubType |= subType;
          }
        }
        Assert.AreEqual(expectedCpuSubType, fileSection.CpuSubType, $"{indexMsg}, expected 0x{expectedCpuSubType:X}, but was 0x{fileSection.CpuSubType:X}");

        Assert.AreEqual(sectionData.mhFileType, fileSection.MhFileType, indexMsg);

        // Parse options
        Options expectedOptions = 0;
        if (!string.IsNullOrEmpty(sectionData.options) && sectionData.options != "0")
        {
          foreach (var optionName in sectionData.options.Split('|').Select(s => s.Trim()))
          {
            var option = (Options)Enum.Parse(typeof(Options), optionName);
            expectedOptions |= option;
          }
        }

        var hasSignedBlob = (expectedOptions & Options.HasSignedBlob) == Options.HasSignedBlob;
        var hasCmsBlob = (expectedOptions & Options.HasCmsBlob) == Options.HasCmsBlob;
        var hasEntitlements = (expectedOptions & Options.HasEntitlements) == Options.HasEntitlements;
        var hasEntitlementsDer = (expectedOptions & Options.HasEntitlementsDer) == Options.HasEntitlementsDer;

        var signedBlob = fileSection.SignatureData.SignedBlob;
        var cmsBlob = fileSection.SignatureData.CmsBlob;
        var entitlements = fileSection.Entitlements;
        var entitlementsDer = fileSection.EntitlementsDer;

        Assert.AreEqual(hasSignedBlob, fileSection.HasSignature, $"{indexMsg} Options.HashSignedBlob mismatch");
        Assert.AreEqual(hasSignedBlob, signedBlob != null, $"{indexMsg} Options.HashSignedBlob mismatch");
        Assert.AreEqual(hasCmsBlob, cmsBlob != null, $"{indexMsg} Options.HasCmsBlob mismatch");
        Assert.AreEqual(hasEntitlements, entitlements != null, $"{indexMsg} Options.HasEntitlements mismatch");
        Assert.AreEqual(hasEntitlementsDer, entitlementsDer != null, $"{indexMsg} Options.HasEntitlementsDer mismatch");

        if (signedBlob != null)
        {
          Assert.AreEqual((byte)0xFA, signedBlob[0], indexMsg);
          Assert.AreEqual((byte)0xDE, signedBlob[1], indexMsg);
          Assert.AreEqual((byte)0x0C, signedBlob[2], indexMsg);
          Assert.AreEqual((byte)0x02, signedBlob[3], indexMsg);

          var length = checked((int)(
            (uint)signedBlob[4] << 24 |
            (uint)signedBlob[5] << 16 |
            (uint)signedBlob[6] << 8 |
            (uint)signedBlob[7] << 0));
          Assert.AreEqual(length, signedBlob.Length, indexMsg);

          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(signedBlob);
          Assert.AreEqual(sectionData.codeDirectoryBlobHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
        {
          Assert.IsFalse(hasCmsBlob);
          Assert.IsNull(sectionData.codeDirectoryBlobHash);
        }

        if (cmsBlob != null)
        {
          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(cmsBlob);
          Assert.AreEqual(sectionData.cmsDataHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
          Assert.IsNull(sectionData.cmsDataHash);

        var computeHashInfo = fileSection.ComputeHashInfo;
        Assert.IsNotNull(computeHashInfo, indexMsg);
        ValidateUtil.Validate(computeHashInfo!, indexMsg);
        Assert.AreEqual(sectionData.orderedIncludeRanges, computeHashInfo!.ToString(), indexMsg);

        if (entitlements != null)
        {
          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(entitlements);

          Assert.AreEqual(sectionData.entitlementsHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
          Assert.Null(sectionData.entitlementsHash, indexMsg);

        if (entitlementsDer != null)
        {
          byte[] hash;
          using (var hashAlgorithm = SHA384.Create())
            hash = hashAlgorithm.ComputeHash(entitlementsDer);

          Assert.AreEqual(sectionData.entitlementsDerHash, HexUtil.ConvertToHexString(hash), indexMsg);
        }
        else
          Assert.Null(sectionData.entitlementsDerHash, indexMsg);
      }

      Console.WriteLine($"INFO: Successfully tested {testCase.resourceName}");
    }

    [TestCase("libclang_rt.cc_kext.a")]
    [TestCase("libclang_rt.soft_static.a")]
    [Test]
    public void ErrorTest(string resourceName)
    {
      Console.WriteLine($"INFO: Testing error case for MachO file: {resourceName}");

      ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Console.Error.WriteLine($"TRACE: Verifying {resourceName} is not recognized as a MachO file");
          Assert.IsFalse(MachOFile.Is(stream), $"File {resourceName} should not be recognized as a MachO file");

          Console.Error.WriteLine($"TRACE: Verifying parsing {resourceName} throws an exception");
          Assert.That(() => MachOFile.Parse(stream), Throws.Exception, $"Parsing {resourceName} should throw an exception");

          Console.WriteLine($"INFO: Successfully verified error case for {resourceName}");
          return false;
        });
    }

  }
}