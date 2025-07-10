using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Dmg;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
{
  public class TestCase
  {
    public string testType { get; set; }
    public string resourceName { get; set; }
    public ResourceCategory resourceCategory { get; set; }
    public bool? hasSignature { get; set; }
    public string description { get; set; }
  }

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

    return ResourceUtil.OpenRead(ResourceCategory.TestCases, "DmgFileTestCases.json", stream =>
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

  [TestCaseSource(nameof(LoadValidDmgTestCases))]
  [Test]
  public void TestValidDmgFile_ShouldParseCorrectly(TestCase testCase)
  {
    Console.WriteLine($"INFO: Testing valid DMG file: {testCase.resourceName}");

    var file = ResourceUtil.OpenRead(testCase.resourceCategory, testCase.resourceName, stream =>
    {
      Console.Error.WriteLine($"TRACE: Parsing DMG file: {testCase.resourceName}");
      Assert.IsTrue(DmgFile.Is(stream), $"File {testCase.resourceName} should be recognized as a DMG file");
      return DmgFile.Parse(stream, DmgFile.Mode.SignatureData);
    });

    var expectedHasSignature = testCase.hasSignature ?? false;
    Assert.AreEqual(expectedHasSignature, file.HasSignature,
      $"File {testCase.resourceName} signature status mismatch. Expected: {expectedHasSignature}, Actual: {file.HasSignature}");

    Console.WriteLine($"INFO: Successfully tested {testCase.resourceName} - HasSignature: {file.HasSignature}");
  }

  [TestCaseSource(nameof(LoadNonDmgTestCases))]
  [Test]
  public void TestNonDmgFile_ShouldNotBeRecognizedAsDmg(TestCase testCase)
  {
    Console.WriteLine($"INFO: Testing non-DMG file: {testCase.resourceName}");

    ResourceUtil.OpenRead(testCase.resourceCategory, testCase.resourceName, stream =>
    {
      Console.Error.WriteLine($"TRACE: Checking if file is DMG: {testCase.resourceName}");
      Assert.IsFalse(DmgFile.Is(stream), $"File {testCase.resourceName} should NOT be recognized as a DMG file");
      return 0;
    });

    Console.WriteLine($"INFO: Successfully verified {testCase.resourceName} is not a DMG file");
  }
}