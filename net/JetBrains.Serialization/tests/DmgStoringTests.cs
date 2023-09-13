using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Pe;
using JetBrains.Serialization.FileInfos.Dmg;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.Serialization.Tests;

public class  DmgStoringTests
{
  // @formatter:off
  [TestCase("steam.dmg", "steam_not_signed.dmg")]
  [TestCase("dd.dmg", "dd_not_signed.dmg")]
  // @formatter:on
  public Task DmgStoringTest(string signedResourceName, string unsignedResourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, signedResourceName,
      stream => DmgFile.Parse(stream));

    var initialFileInfo = new DmgFileInfo(file);

    var settings = new JsonSerializerSettings
    {
      TypeNameHandling = TypeNameHandling.Auto
    };
    var json = JsonConvert.SerializeObject(initialFileInfo, settings);
    var fileInfo = JsonConvert.DeserializeObject<DmgFileInfo>(json, settings)!;


    var tmpFile = Path.GetTempFileName();
    ResourceUtil.OpenRead(ResourceCategory.Dmg, unsignedResourceName,
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

    ResourceUtil.OpenRead(ResourceCategory.Dmg, signedResourceName,
      stream =>
      {
        Assert.That(ResourceUtil.CompareTwoStreams(stream, new FileStream(tmpFile, FileMode.Open, FileAccess.Read)));
        return true;
      });


    return Task.CompletedTask;
  }
}