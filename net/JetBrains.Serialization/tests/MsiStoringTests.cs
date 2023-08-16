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
  // @formatter:on
  public Task MsiStoringTest(string signedResourceName, string unsignedResourceName)
  {
    MsiFileInfo? initialFileInfo = null;

    var file = ResourceUtil.OpenRead(ResourceCategory.Msi, signedResourceName,
      stream =>
      {
        var compoundFile = CompoundFile.Parse(stream, CompoundFile.Mode.SignatureData);
        initialFileInfo = new MsiFileInfo(compoundFile);
        return compoundFile;
      });


    // var settings = new JsonSerializerSettings
    // {
    //   TypeNameHandling = TypeNameHandling.Auto
    // };
    // var json = JsonConvert.SerializeObject(initialFileInfo, settings);
    // var fileInfo = JsonConvert.DeserializeObject<MsiFileInfo>(json, settings)!;
    //
    //
    var tmpFile = Path.GetTempFileName();
    ResourceUtil.OpenRead(ResourceCategory.Msi, signedResourceName,
      stream =>
      {
        using (var fileStream = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
        {
          stream.CopyTo(fileStream);
        }

        return true;
      });

    using (var fileStream = new FileStream(tmpFile, FileMode.Open, FileAccess.Read))
    {
      using (var dstStream = new FileStream("/Users/artemkaramysev/Desktop/projects/work/format-ripper/data/msi/tmp",
               FileMode.Create, FileAccess.ReadWrite))
      {
        initialFileInfo!.ModifyFile(fileStream);
        fileStream.CopyTo(dstStream);
      }
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