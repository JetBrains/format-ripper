using JetBrains.FormatRipper.Pe;
using JetBrains.Serialization.FileInfos.PE;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.Serialization.Tests;

public class PeStoringTests
{
  // @formatter:off
   [TestCase("ServiceModelRegUI.dll", "ServiceModelRegUI_no_sign.dll")]
   [TestCase("shell32.dll", "shell32_no_sign.dll")]
   [TestCase("IntelAudioService.exe", "IntelAudioService_no_sign.exe")]
   [TestCase("libcrypto-1_1-x64.dll", "libcrypto-1_1-x64_no_sign.dll")]
   [TestCase("libssl-1_1-x64.dll", "libssl-1_1-x64_no_sign.dll")]
   [TestCase("JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe", "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web_no_sign.exe")]
   [TestCase("dotnet.exe", "dotnet_no_sign.exe")]
  // @formatter:on
  public Task PeStoringTest(string signedResourceName, string unsignedResourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Pe, signedResourceName,
      stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

    var initialFileInfo = new PeFileInfo(file);

    var settings = new JsonSerializerSettings
    {
      TypeNameHandling = TypeNameHandling.Auto
    };
    var json = JsonConvert.SerializeObject(initialFileInfo, settings);
    var fileInfo = JsonConvert.DeserializeObject<PeFileInfo>(json, settings)!;


    var tmpFile = Path.GetTempFileName();
    ResourceUtil.OpenRead(ResourceCategory.Pe, unsignedResourceName,
      stream =>
      {
        using (var fileStream = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
        {
          stream.CopyTo(fileStream);
        }

        return true;
      });

    using (var fileStream = new FileStream(tmpFile, FileMode.Open, FileAccess.Write))
    {
      fileInfo.ModifyFile(fileStream);
    }

    ResourceUtil.OpenRead(ResourceCategory.Pe, signedResourceName,
      stream =>
      {
        Assert.That(ResourceUtil.CompareTwoStreams(stream, new FileStream(tmpFile, FileMode.Open, FileAccess.Read)));
        return true;
      });


    return Task.CompletedTask;
  }
}