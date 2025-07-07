using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Dmg;
using JetBrains.SignatureVerifier;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
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
    public string testType { get; set; }
    public string resourceName { get; set; }
    public string resourceCategory { get; set; }
    public bool? hasSignature { get; set; }
    public string description { get; set; }
  }

  private static readonly ILogger Logger = ConsoleLogger.Instance;

  private static IEnumerable<TestCaseData> LoadValidDmgTestCases()
  {
    var testCases = LoadTestCases().Where(tc => tc.testType == "validDmg");
    
    return testCases.Select(testCase =>
      new TestCaseData(testCase)
        .SetName($"ValidDmg_{testCase.resourceName.Replace(".", "_").Replace("-", "_")}")
        .SetDescription($"Test DMG file parsing for {testCase.resourceName} - {testCase.description}")
    );
  }

  private static IEnumerable<TestCaseData> LoadNonDmgTestCases()
  {
    var testCases = LoadTestCases().Where(tc => tc.testType == "nonDmg");
    
    return testCases.Select(testCase =>
      new TestCaseData(testCase)
        .SetName($"NonDmg_{testCase.resourceName.Replace(".", "_").Replace("-", "_").Replace(" ", "_")}")
        .SetDescription($"Test non-DMG file detection for {testCase.resourceName} - {testCase.description}")
    );
  }

  private static List<TestCase> LoadTestCases()
  {
    var type = typeof(ResourceUtil);
    var resourceName = $"{type.Namespace}.DmgFileTestCases.json";

    using var stream = type.Assembly.GetManifestResourceStream(resourceName);
    if (stream == null)
      throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");

    using var reader = new StreamReader(stream);
    var json = reader.ReadToEnd();
    return JsonConvert.DeserializeObject<List<TestCase>>(json);
  }

  [TestCaseSource(nameof(LoadValidDmgTestCases))]
  [Test]
  public void TestValidDmgFile_ShouldParseCorrectly(TestCase testCase)
  {
    Logger.Info($"Testing valid DMG file: {testCase.resourceName}");
    
    var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
    var file = ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, stream =>
    {
      Logger.Trace($"Parsing DMG file: {testCase.resourceName}");
      Assert.IsTrue(DmgFile.Is(stream), $"File {testCase.resourceName} should be recognized as a DMG file");
      return DmgFile.Parse(stream, DmgFile.Mode.SignatureData);
    });

    var expectedHasSignature = testCase.hasSignature ?? false;
    Assert.AreEqual(expectedHasSignature, file.HasSignature, 
      $"File {testCase.resourceName} signature status mismatch. Expected: {expectedHasSignature}, Actual: {file.HasSignature}");
    
    Logger.Info($"Successfully tested {testCase.resourceName} - HasSignature: {file.HasSignature}");
  }

  [TestCaseSource(nameof(LoadNonDmgTestCases))]
  [Test]
  public void TestNonDmgFile_ShouldNotBeRecognizedAsDmg(TestCase testCase)
  {
    Logger.Info($"Testing non-DMG file: {testCase.resourceName}");
    
    var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
    ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, stream =>
    {
      Logger.Trace($"Checking if file is DMG: {testCase.resourceName}");
      Assert.IsFalse(DmgFile.Is(stream), $"File {testCase.resourceName} should NOT be recognized as a DMG file");
      return 0;
    });
    
    Logger.Info($"Successfully verified {testCase.resourceName} is not a DMG file");
  }
}