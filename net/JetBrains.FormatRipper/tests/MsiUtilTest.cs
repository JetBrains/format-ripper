using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Compound;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class MsiUtilTest
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
      public string name { get; set; }
      public string expectedName { get; set; }
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

    private static IEnumerable<TestCaseData> LoadMsiTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"MsiDecode_{testCase.expectedName.Replace(".", "_")}")
          .SetDescription($"Test MSI stream name decoding for {testCase.description}")
      );
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.MsiUtilTestCases.json";

      return ResourceUtil.OpenRead(ResourceCategory.TestCases, "MsiUtilTestCases.json", stream =>
      {
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var obj = JsonConvert.DeserializeObject<List<TestCase>>(json);
        if (obj == null)
          throw new InvalidOperationException($"Failed to deserialize test cases from {resourceName}");
        return obj;
      });
    }

    [TestCaseSource(nameof(LoadMsiTestCases))]
    [Test]
    public void TestMsiDecodeStreamName(TestCase testCase)
    {
      Logger.Info($"Testing MSI stream name decoding: {testCase.description}");

      if (testCase.name.StartsWith("DirectoryNames."))
      {
        var directoryName = testCase.name.Replace("DirectoryNames.", "");
        var fieldInfo = typeof(DirectoryNames).GetField(directoryName);
        if (fieldInfo != null)
        {
          var value = fieldInfo.GetValue(null);
          if (value != null)
          {
            testCase.name = value as string;
          }
        }
      }

      if (testCase.expectedName.StartsWith("DirectoryNames."))
      {
        var directoryName = testCase.expectedName.Replace("DirectoryNames.", "");
        var fieldInfo = typeof(DirectoryNames).GetField(directoryName);
        if (fieldInfo != null)
        {
          var value = fieldInfo.GetValue(null);
          if (value != null)
          {
            testCase.expectedName = value as string;
          }
        }
      }


      string decodedName = MsiUtil.MsiDecodeStreamName(testCase.name);

      Assert.AreEqual(testCase.expectedName, decodedName,
        $"Failed to decode MSI stream name '{testCase.name}' correctly");

      Logger.Info($"Successfully decoded '{testCase.name}' to '{decodedName}'");
    }
  }
}