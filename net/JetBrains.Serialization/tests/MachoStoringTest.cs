using JetBrains.FormatRipper.MachO;
using JetBrains.Serialization.FileInfos.MachO;
using Newtonsoft.Json;
using NUnit.Framework;

namespace JetBrains.Serialization.Tests;

public class MachoStoringTest
{
  private static MachOFile GetMachOFile(string resourceName) => ResourceUtil.OpenRead(ResourceCategory.MachO,
    resourceName, stream => MachOFile.Parse(stream, MachOFile.Mode.SignatureData | MachOFile.Mode.Serialization));

  // @formatter:off
   [TestCase("addhoc_resigned", "addhoc")]
   [TestCase("nosigned_resigned", "notsigned")]
   [TestCase("fat.dylib_signed", "fat.dylib")]
   [TestCase("JetBrains.Profiler.PdbServer", "JetBrains.Profiler.PdbServer")]
   [TestCase("cat", "cat")]
   [TestCase("env-wrapper.x64", "env-wrapper.x64")]
   [TestCase("libMonoSupportW.x64.dylib", "libMonoSupportW.x64.dylib")]
   [TestCase("libhostfxr.dylib", "libhostfxr.dylib")]
  // @formatter:on
  public Task StoringTest(string signedResourceName, string unsignedResourceName)
  {
    var file = GetMachOFile(signedResourceName);
    var fileInfo = new MachoArchInfo(file);

    var tmpFile = Path.GetTempFileName();
    ResourceUtil.OpenRead(ResourceCategory.MachO, unsignedResourceName,
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

    // using (var targetPath = new FileStream("./tmps/tmp", FileMode.Create, FileAccess.ReadWrite))
    // {
      // using (var fileStream = new FileStream(tmpFile, FileMode.Open, FileAccess.ReadWrite))
      // {
        // fileStream.CopyTo(targetPath);
      // }
    // }


    ResourceUtil.OpenRead(ResourceCategory.MachO, signedResourceName,
      stream =>
      {
        Assert.That(ResourceUtil.CompareTwoStreams(stream, new FileStream(tmpFile, FileMode.Open, FileAccess.Read)));
        return true;
      });


    return Task.CompletedTask;
  }
}