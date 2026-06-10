using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class MachOFileTest
  {
    // Local logger implementation for test output
    private sealed class ConsoleLogger : ILogger
    {
      public static readonly ILogger Instance = new ConsoleLogger();
      private ConsoleLogger() { }
      public void Info(string str) => Console.WriteLine($"INFO: {str}");
      public void Warning(string str) => Console.Error.WriteLine($"WARNING: {str}");
      public void Error(string str) => Console.Error.WriteLine($"ERROR: {str}");
      public void Trace(string str) => Console.Error.WriteLine($"TRACE: {str}");
    }

    public class TestCase
    {
      public string resourceName { get; set; }
      public string resourceCategory { get; set; }
      public bool? isFatLittleEndian { get; set; }
      public SectionData[] sections { get; set; }
      public string description { get; set; }
    }

    public class SectionData
    {
      public bool isLittleEndian { get; set; }
      public string cpuType { get; set; }
      public string cpuSubType { get; set; }
      public string mhFileType { get; set; }
      public string options { get; set; }
      public string codeDirectoryBlobHash { get; set; }
      public string cmsDataHash { get; set; }
      public string orderedIncludeRanges { get; set; }
      public string entitlementsHash { get; set; }
      public string entitlementsDerHash { get; set; }
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

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

      using var stream = type.Assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");

      using var reader = new StreamReader(stream);
      var json = reader.ReadToEnd();
      return JsonConvert.DeserializeObject<List<TestCase>>(json);
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
      Logger.Info($"Testing MachO file: {testCase.resourceName}");

      var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
      var file = ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, stream =>
        {
          Logger.Trace($"Parsing MachO file: {testCase.resourceName}");
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

        Logger.Trace($"Testing section {n} of {testCase.resourceName}: {sectionData.description}");

        Assert.AreEqual(sectionData.isLittleEndian, fileSection.IsLittleEndian, indexMsg);

        var expectedCpuType = Enum.Parse<CPU_TYPE>(sectionData.cpuType);
        Assert.AreEqual(expectedCpuType, fileSection.CpuType, indexMsg);

        // Handle complex CPU subtypes with bitwise OR
        CPU_SUBTYPE expectedCpuSubType = 0;
        if (!string.IsNullOrEmpty(sectionData.cpuSubType))
        {
          foreach (var subTypeName in sectionData.cpuSubType.Split('|').Select(s => s.Trim()))
          {
            var subType = Enum.Parse<CPU_SUBTYPE>(subTypeName);
            expectedCpuSubType |= subType;
          }
        }
        Assert.AreEqual(expectedCpuSubType, fileSection.CpuSubType, $"{indexMsg}, expected 0x{expectedCpuSubType:X}, but was 0x{fileSection.CpuSubType:X}");

        var expectedMhFileType = Enum.Parse<MH_FileType>(sectionData.mhFileType);
        Assert.AreEqual(expectedMhFileType, fileSection.MhFileType, indexMsg);

        // Parse options
        Options expectedOptions = 0;
        if (!string.IsNullOrEmpty(sectionData.options) && sectionData.options != "0")
        {
          foreach (var optionName in sectionData.options.Split('|').Select(s => s.Trim()))
          {
            var option = Enum.Parse<Options>(optionName);
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

      Logger.Info($"Successfully tested {testCase.resourceName}");
    }

    [TestCase("libclang_rt.cc_kext.a")]
    [TestCase("libclang_rt.soft_static.a")]
    [Test]
    public void ErrorTest(string resourceName)
    {
      Logger.Info($"Testing error case for MachO file: {resourceName}");

      ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream =>
        {
          Logger.Trace($"Verifying {resourceName} is not recognized as a MachO file");
          Assert.IsFalse(MachOFile.Is(stream), $"File {resourceName} should not be recognized as a MachO file");

          Logger.Trace($"Verifying parsing {resourceName} throws an exception");
          Assert.That(() => MachOFile.Parse(stream), Throws.Exception, $"Parsing {resourceName} should throw an exception");

          Logger.Info($"Successfully verified error case for {resourceName}");
          return false;
        });
    }

  }
}