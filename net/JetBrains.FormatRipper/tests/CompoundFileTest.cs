using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using JetBrains.FormatRipper.Compound;
using NUnit.Framework;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace JetBrains.FormatRipper.Tests
{
  [TestFixture]
  public sealed class CompoundFileTest
  {
    public class TestCase
    {
      public string resourceName { get; set; }
      public string expectedType { get; set; }
      public string[] expectedOptions { get; set; }
      public string expectedCmsBlobHash { get; set; }
      public string expectedOrderedIncludeRanges { get; set; }
      public StreamInfo[] expectedStreams { get; set; }
    }

    public class StreamInfo
    {
      public string hash { get; set; }
      public string clsid { get; set; }
      public string[] names { get; set; }
    }

    private static IEnumerable<TestCaseData> LoadTestCases()
    {
      var type = typeof(ResourceUtil);
      var resourceName = $"{type.Namespace}.CompoundFileTestCases.json";

      var testCases = ResourceUtil.OpenRead(ResourceCategory.TestCases, "CompoundFileTestCases.json", stream =>
      {
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var obj = JsonConvert.DeserializeObject<List<TestCase>>(json);
        if (obj == null)
          throw new InvalidOperationException($"Failed to deserialize test cases from {resourceName}");
        return obj;
      });

      return testCases.Select(testCase =>
        new TestCaseData(testCase)
          .SetName($"{testCase.resourceName.Replace(".", "_")}")
          .SetDescription($"Test CompoundFile parsing for {testCase.resourceName} (Type: {testCase.expectedType})")
      );
    }

    [TestCaseSource(nameof(LoadTestCases))]
    [Test]
    public void Test(TestCase testCase)
    {
      Console.WriteLine($"Testing resource: {testCase.resourceName}");

      var file = ResourceUtil.OpenRead(ResourceCategory.Msi, testCase.resourceName, stream =>
      {
        Assert.IsTrue(CompoundFile.Is(stream));
        return CompoundFile.Parse(stream, CompoundFile.Mode.SignatureData | CompoundFile.Mode.ComputeHashInfo, (_, _, _) => true);
      });

      var expectedType = (CompoundFile.FileType)Enum.Parse(typeof(CompoundFile.FileType), testCase.expectedType);
      Assert.AreEqual(expectedType, file.Type);

      var hasCmsBlob = testCase.expectedOptions.Contains("HasCmsBlob");
      var signedBlob = file.SignatureData.SignedBlob;
      var cmsBlob = file.SignatureData.CmsBlob;

      Assert.AreEqual(hasCmsBlob, file.HasSignature);
      Assert.IsNull(signedBlob);
      Assert.AreEqual(hasCmsBlob, cmsBlob != null);

      if (cmsBlob != null)
      {
        byte[] hash;
        using (var hashAlgorithm = SHA384.Create())
          hash = hashAlgorithm.ComputeHash(cmsBlob);
        Assert.AreEqual(testCase.expectedCmsBlobHash, HexUtil.ConvertToHexString(hash));
      }
      else
        Assert.IsNull(testCase.expectedCmsBlobHash);

      var fileExtractStreams = new List<CompoundFile.ExtractStream>(file.ExtractStreams);
      fileExtractStreams.Sort((x, y) =>
      {
        var minSize = Math.Min(x.Names.Length, y.Names.Length);
        for (var n = 0; n < minSize; ++n)
        {
          var res = string.CompareOrdinal(x.Names[n], y.Names[n]);
          if (res != 0)
            return res;
        }
        return x.Names.Length - y.Names.Length;
      });

      Assert.AreEqual(testCase.expectedStreams.Length, fileExtractStreams.Count);
      for (var n = 0; n < testCase.expectedStreams.Length; ++n)
      {
        Assert.AreEqual(new Guid(testCase.expectedStreams[n].clsid), fileExtractStreams[n].Clsid);
        Assert.AreEqual(testCase.expectedStreams[n].names.Length, fileExtractStreams[n].Names.Length);
        for (var k = 0; k < testCase.expectedStreams[n].names.Length; ++k)
          Assert.AreEqual(testCase.expectedStreams[n].names[k], fileExtractStreams[n].Names[k]);
        byte[] hash;
        using (var hashAlgorithm = SHA256.Create())
          hash = hashAlgorithm.ComputeHash(fileExtractStreams[n].Blob);
        Assert.AreEqual(testCase.expectedStreams[n].hash, HexUtil.ConvertToHexString(hash));
      }

      var computeHashInfo = file.ComputeHashInfo;
      Assert.IsNotNull(computeHashInfo);
      Assert.AreEqual(testCase.expectedOrderedIncludeRanges, computeHashInfo!.ToString());

      Console.WriteLine($"✓ Successfully tested {testCase.resourceName} (Type: {testCase.expectedType})");
    }
  }
}