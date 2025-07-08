using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Sh;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ShFileTest
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
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

    private static IEnumerable<TestCaseData> LoadShTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"Sh_{testCase.resourceName.Replace(".", "_")}")
          .SetDescription(testCase.description)
      );
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.ShFileTestCases.json";

      using var stream = type.Assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");

      using var reader = new StreamReader(stream);
      var json = reader.ReadToEnd();
      return JsonConvert.DeserializeObject<List<TestCase>>(json);
    }

    [TestCaseSource(nameof(LoadShTestCases))]
    [Test]
    public void TestShFile(TestCase testCase)
    {
      Logger.Info($"Testing shell script file: {testCase.resourceName}");

      var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
      ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, stream =>
      {
        Logger.Trace($"Checking if {testCase.resourceName} is a shell script file");
        Assert.IsTrue(ShFile.Is(stream), $"File {testCase.resourceName} should be recognized as a shell script file");
        Logger.Info($"Successfully verified {testCase.resourceName} is a shell script file");
        return false;
      });
    }
  }
}