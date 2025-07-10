using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Elf;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ElfFileTest
  {
    public class TestCase
    {
      public string resourceName { get; set; }
      public ResourceCategory resourceCategory { get; set; }
      public ELFCLASS eiClass { get; set; }
      public ELFDATA eiData { get; set; }
      public ELFOSABI eiOsAbi { get; set; }
      public ET eType { get; set; }
      public EM eMachine { get; set; }
      public object eFlags { get; set; }
      public string interpreter { get; set; }
      public string description { get; set; }
    }

    private static IEnumerable<TestCaseData> LoadElfTestCases()
    {
      var testCases = LoadTestCases();

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"Elf_{testCase.resourceName.Replace(".", "_").Replace("-", "_")}")
          .SetDescription($"Test ELF file parsing for {testCase.resourceName} - {testCase.description}")
      );
    }

    private static List<TestCase> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.ElfFileTestCases.json";

      return ResourceUtil.OpenRead(ResourceCategory.TestCases, "ElfFileTestCases.json", stream =>
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

    [TestCaseSource(nameof(LoadElfTestCases))]
    [Test]
    public void TestElfFile(TestCase testCase)
    {
      Console.WriteLine($"INFO: Testing ELF file: {testCase.resourceName}");

      var file = ResourceUtil.OpenRead(testCase.resourceCategory, testCase.resourceName, stream =>
      {
        Console.Error.WriteLine($"TRACE: Parsing ELF file: {testCase.resourceName}");
        Assert.IsTrue(ElfFile.Is(stream), $"File {testCase.resourceName} should be recognized as an ELF file");
        return ElfFile.Parse(stream);
      });


      // Handle eFlags which can be either a number or a string expression
      EF expectedEFlags;
      if (testCase.eFlags is long || testCase.eFlags is int)
      {
        expectedEFlags = (EF)Convert.ToUInt32(testCase.eFlags);
      }
      else
      {
        var flagsStr = testCase.eFlags.ToString();
        if (string.IsNullOrEmpty(flagsStr) || flagsStr == "0")
        {
          expectedEFlags = 0;
        }
        else if (flagsStr == "EF_NONE")
        {
          expectedEFlags = EF.EF_NONE;
        }
        else
        {
          // Parse flag expressions like "EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_HARD"
          expectedEFlags = 0;
          foreach (var flagName in flagsStr.Split('|').Select(f => f.Trim()))
          {
            var flag = (EF)Enum.Parse(typeof(EF), flagName);
            expectedEFlags |= flag;
          }
        }
      }

      Assert.AreEqual(testCase.eiClass, file.EiClass, $"EiClass mismatch for {testCase.resourceName}");
      Assert.AreEqual(testCase.eiData, file.EiData, $"EiData mismatch for {testCase.resourceName}");
      Assert.AreEqual(testCase.eiOsAbi, file.EiOsAbi, $"EiOsAbi mismatch for {testCase.resourceName}");
      Assert.AreEqual(testCase.eType, file.EType, $"EType mismatch for {testCase.resourceName}");
      Assert.AreEqual(testCase.eMachine, file.EMachine, $"EMachine mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEFlags, file.EFlags, $"EFlags mismatch for {testCase.resourceName}. Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
      Assert.AreEqual(testCase.interpreter, file.Interpreter, $"Interpreter mismatch for {testCase.resourceName}");

      Console.WriteLine($"INFO: Successfully tested {testCase.resourceName}");
    }
  }
}