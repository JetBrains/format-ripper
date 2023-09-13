using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Pe;
using JetBrains.Serialization.FileInfos.Msi;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.Serialization.Tests;

public class MsiStoringTests
{
// @formatter:off
    [TestCase("2dac4b.msi", "2dac4b_not_signed.msi")]
    [TestCase("2dac4b_signed2.msi", "2dac4b_not_signed.msi")]
    [TestCase("firefox.msi", "firefox_not_signed.msi")]
    [TestCase("sumatra.msi", "sumatra_not_signed.msi")]

  // @formatter:on
  public Task MsiStoringTest(string signedResourceName, string unsignedResourceName)
  {
    MsiFileInfo? initialFileInfo = null;

    var file = ResourceUtil.OpenRead(ResourceCategory.Msi, signedResourceName,
      stream =>
      {
        var compoundFile = CompoundFile.Parse(stream, CompoundFile.Mode.SIGNATURE_DATA);
        initialFileInfo = new MsiFileInfo(compoundFile);
        return compoundFile;
      });


    var settings = new JsonSerializerSettings
    {
      TypeNameHandling = TypeNameHandling.Auto
    };
    var json = JsonConvert.SerializeObject(initialFileInfo, settings);
    var fileInfo = JsonConvert.DeserializeObject<MsiFileInfo>(json, settings)!;

    var tmpFile = Path.GetTempFileName();
    ResourceUtil.OpenRead(ResourceCategory.Msi, unsignedResourceName,
      stream =>
      {
        using (var fileStream = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
        {
          stream.CopyTo(fileStream);
        }

        return true;
      });

    using (var fileStream = new FileStream(tmpFile, FileMode.Open, FileAccess.ReadWrite))
    {
      fileInfo.ModifyFile(fileStream);
    }

    ResourceUtil.OpenRead(ResourceCategory.Msi, signedResourceName,
      stream =>
      {
        Assert.That(ResourceUtil.CompareTwoStreams(stream, new FileStream(tmpFile, FileMode.Open, FileAccess.Read)));
        return true;
      });

    return Task.CompletedTask;
  }
}