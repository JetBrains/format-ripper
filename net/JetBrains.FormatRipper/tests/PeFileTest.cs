using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.FormatRipper.Pe;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class PeFileTest
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

    [Flags]
    public enum CodeOptions
    {
      HasCmsBlob = 0x1,
      HasMetadata = 0x2
    }

    public class TestCase
    {
      public string resourceName { get; set; }
      public string expectedMachine { get; set; }
      public string expectedSubsystem { get; set; }
      public string[] expectedCharacteristics { get; set; }
      public string expectedOptions { get; set; }
      public string expectedCmsBlobHash { get; set; }
      public string expectedSecurityDataDirectoryRange { get; set; }
      public string expectedOrderedIncludeRanges { get; set; }
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

    private static IEnumerable<TestCaseData> LoadPeTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
      {
        // Parse the enum values from strings
        var machine = (IMAGE_FILE_MACHINE)Enum.Parse(typeof(IMAGE_FILE_MACHINE), testCase.expectedMachine);
        var subsystem = (IMAGE_SUBSYSTEM)Enum.Parse(typeof(IMAGE_SUBSYSTEM), testCase.expectedSubsystem);

        // Parse the characteristics flags
        IMAGE_FILE characteristics = 0;
        foreach (var flag in testCase.expectedCharacteristics)
        {
          var enumValue = (IMAGE_FILE)Enum.Parse(typeof(IMAGE_FILE), flag);
          characteristics |= enumValue;
        }

        // Parse the options flags
        CodeOptions options = 0;
        if (testCase.expectedOptions != "0")
        {
          foreach (var flag in testCase.expectedOptions.Split('|', StringSplitOptions.RemoveEmptyEntries))
          {
            var trimmedFlag = flag.Trim();
            var enumValue = (CodeOptions)Enum.Parse(typeof(CodeOptions), trimmedFlag);
            options |= enumValue;
          }
        }

        return new TestCaseData(
            testCase.resourceName,
            machine,
            subsystem,
            characteristics,
            options,
            testCase.expectedCmsBlobHash,
            testCase.expectedSecurityDataDirectoryRange,
            testCase.expectedOrderedIncludeRanges
          )
          .SetName($"PeFile_{testCase.resourceName}")
          .SetDescription(testCase.description);
      });
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.PeFileTestCases.json";

      return ResourceUtil.OpenRead(ResourceCategory.TestCases, "PeFileTestCases.json", stream =>
      {
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var obj = JsonConvert.DeserializeObject<List<TestCase>>(json);
        if (obj == null)
          throw new InvalidOperationException($"Failed to deserialize test cases from {resourceName}");
        return obj;
      });
    }

    [TestCaseSource(nameof(LoadPeTestCases))]
    public void Test(
      string resourceName,
      IMAGE_FILE_MACHINE expectedMachine,
      IMAGE_SUBSYSTEM expectedSubsystem,
      IMAGE_FILE expectedCharacteristics,
      CodeOptions expectedOptions,
      string expectedCmsBlobHash,
      string expectedSecurityDataDirectoryRange,
      string expectedOrderedIncludeRanges)
    {
      Logger.Info($"Testing PE file: {resourceName}");

      var file = ResourceUtil.OpenRead(ResourceCategory.Pe, resourceName, stream =>
        {
          Assert.IsTrue(PeFile.Is(stream));
          return PeFile.Parse(stream, PeFile.Mode.SignatureData | PeFile.Mode.ComputeHashInfo);
        });

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

      Logger.Info($"Successfully tested PE file: {resourceName}");
    }
  }
}