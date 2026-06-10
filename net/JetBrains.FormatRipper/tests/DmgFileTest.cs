using JetBrains.FormatRipper.Dmg;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
{
  // @formatter:off
  [TestCase("test.dmg",           false)]
  [TestCase("test-signed.dmg"   , true)]
  [TestCase("license.dmg",        false)]
  [TestCase("license-signed.dmg", true)]
  // @formatter:on
  public void TestDmgWithValidParameters(string resourceName, bool hasSignature)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, stream =>
    {
      Assert.IsTrue(DmgFile.Is(stream));
      return DmgFile.Parse(stream, DmgFile.Mode.SignatureData);
    });

    Assert.AreEqual(hasSignature, file.HasSignature);
  }

  // @formatter:off
  [TestCase("addhoc",                                ResourceCategory.MachO)]
  [TestCase("libhostfxr.dylib",                      ResourceCategory.MachO)]
  [TestCase("System.Security.Principal.Windows.dll", ResourceCategory.Pe)]
  [TestCase("busybox.alpine-s390x",                  ResourceCategory.Elf)]
  [TestCase("test-encrypted-aes128.dmg",             ResourceCategory.Dmg)] // Encrypted DMGs have a different structure and are not yet supported.
  [TestCase("test-encrypted-aes256.dmg",             ResourceCategory.Dmg)]
  [TestCase("test-encrypted-aes128-signed.dmg",      ResourceCategory.Dmg)]
  [TestCase("test-encrypted-aes256-signed.dmg",      ResourceCategory.Dmg)]
  // @formatter:on
  public void TestNonDmgFile(string resourceName, ResourceCategory resourceCategory)
  {
    ResourceUtil.OpenRead(resourceCategory, resourceName, stream =>
    {
      Assert.IsFalse(DmgFile.Is(stream));
      return 0;
    });
  }
}