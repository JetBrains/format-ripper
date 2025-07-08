using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.FileExplorer;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  // Logger interface for test output
  public interface ILogger
  {
    void Info(string str);
    void Warning(string str);
    void Error(string str);
    void Trace(string str);
  }
  [TestFixture]
  public class FileTypeExplorerTest
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
      public string expectedFileType { get; set; }
      public string[] expectedFileProperties { get; set; }
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

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

      using var stream = type.Assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");

      using var reader = new StreamReader(stream);
      var json = reader.ReadToEnd();
      return JsonConvert.DeserializeObject<List<TestCase>>(json);
    }

    [TestCaseSource(nameof(LoadFileTypeExplorerTestCases))]
    [Test]
    public void TestFileTypeDetection(TestCase testCase)
    {
      Logger.Info($"Testing file type detection for: {testCase.resourceName}");

      var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
      var expectedFileType = Enum.Parse<FileType>(testCase.expectedFileType);

      // Parse file properties from the array
      FileProperties expectedFileProperties = 0;
      foreach (var propName in testCase.expectedFileProperties)
      {
        var prop = Enum.Parse<FileProperties>(propName.Trim());
        expectedFileProperties |= prop;
      }

      var (fileType, fileProperties) = ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, FileTypeExplorer.Detect);

      Assert.AreEqual(expectedFileType, fileType, $"File type mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedFileProperties, fileProperties, $"File properties mismatch for {testCase.resourceName}");

      Logger.Info($"Successfully tested {testCase.resourceName}: {fileType}, {fileProperties}");
    }
  }
}