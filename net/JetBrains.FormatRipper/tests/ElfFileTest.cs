using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper.Elf;
using JetBrains.SignatureVerifier;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class ElfFileTest
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
      public string eiClass { get; set; }
      public string eiData { get; set; }
      public string eiOsAbi { get; set; }
      public string eType { get; set; }
      public string eMachine { get; set; }
      public object eFlags { get; set; }
      public string interpreter { get; set; }
      public string description { get; set; }
    }

    private static readonly ILogger Logger = ConsoleLogger.Instance;

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

      using var stream = type.Assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");

      using var reader = new StreamReader(stream);
      var json = reader.ReadToEnd();
      return JsonConvert.DeserializeObject<List<TestCase>>(json);
    }

    [TestCaseSource(nameof(LoadElfTestCases))]
    [Test]
    public void TestElfFile(TestCase testCase)
    {
      Logger.Info($"Testing ELF file: {testCase.resourceName}");

      var resourceCategory = Enum.Parse<ResourceCategory>(testCase.resourceCategory);
      var file = ResourceUtil.OpenRead(resourceCategory, testCase.resourceName, stream =>
      {
        Logger.Trace($"Parsing ELF file: {testCase.resourceName}");
        Assert.IsTrue(ElfFile.Is(stream), $"File {testCase.resourceName} should be recognized as an ELF file");
        return ElfFile.Parse(stream);
      });

      var expectedEiClass = Enum.Parse<ELFCLASS>(testCase.eiClass);
      var expectedEiData = Enum.Parse<ELFDATA>(testCase.eiData);
      var expectedEiOsAbi = Enum.Parse<ELFOSABI>(testCase.eiOsAbi);
      var expectedEType = Enum.Parse<ET>(testCase.eType);
      var expectedEMachine = Enum.Parse<EM>(testCase.eMachine);

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

      Assert.AreEqual(expectedEiClass, file.EiClass, $"EiClass mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEiData, file.EiData, $"EiData mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEiOsAbi, file.EiOsAbi, $"EiOsAbi mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEType, file.EType, $"EType mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEMachine, file.EMachine, $"EMachine mismatch for {testCase.resourceName}");
      Assert.AreEqual(expectedEFlags, file.EFlags, $"EFlags mismatch for {testCase.resourceName}. Expected 0x{expectedEFlags:X}, but was 0x{file.EFlags:X}");
      Assert.AreEqual(testCase.interpreter, file.Interpreter, $"Interpreter mismatch for {testCase.resourceName}");

      Logger.Info($"Successfully tested {testCase.resourceName}");
    }
  }
}