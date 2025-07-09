using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.FileExplorer;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public class FileTypeExplorerTest
  {
    public class TestCase
    {
      public string resourceName { get; set; }
      public string resourceCategory { get; set; }
      public string expectedFileType { get; set; }
      public string[] expectedFileProperties { get; set; }
      public string description { get; set; }
    }

    private static IEnumerable<TestCaseData> LoadFileTypeExplorerTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"FileType_{testCase.resourceName.Replace(".", "_").Replace("-", "_")}")
          .SetDescription($"Test file type detection for {testCase.resourceName} - {testCase.description}")
      );
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.FileTypeExplorerTestCases.json";

      return ResourceUtil.OpenRead(ResourceCategory.TestCases, "FileTypeExplorerTestCases.json", stream =>
      {
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var obj = JsonConvert.DeserializeObject<List<TestCase>>(json);
        if (obj == null)
          throw new InvalidOperationException($"Failed to deserialize test cases from {resourceName}");
        return obj;
      });
    }

    [TestCaseSource(nameof(LoadFileTypeExplorerTestCases))]
    [Test]
    public void TestFileTypeDetection(TestCase testCase)
    {
      Console.WriteLine($"INFO: Testing file type detection for: {testCase.resourceName}");

      var resourceCategory = (ResourceCategory)Enum.Parse(typeof(ResourceCategory), testCase.resourceCategory);
      var expectedFileType = (FileType)Enum.Parse(typeof(FileType), testCase.expectedFileType);

      // Parse file properties from the array
      FileProperties expectedFileProperties = 0;
      foreach (var propName in testCase.expectedFileProperties)
      {
        var prop = (FileProperties)Enum.Parse(typeof(FileProperties), propName.Trim());
        expectedFileProperties |= prop;
      }

      var (fileType, fileProperties) = ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, FileTypeExplorer.Detect);

      Assert.AreEqual(expectedFileType, fileType, $"File type mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedFileProperties, fileProperties, $"File properties mismatch for {testCase.resourceName}");

      Console.WriteLine($"INFO: Successfully tested {testCase.resourceName}: {fileType}, {fileProperties}");
    }
  }
}