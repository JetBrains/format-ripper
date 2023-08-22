using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Dmg;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
{
  // @formatter:off
    [TestCase("steam.dmg", true)]
    [TestCase("steam_not_signed.dmg", false)]
    [TestCase("json-viewer.dmg", true)]
  // @formatter:on
  [Test]
  public void Test(string name, bool hasSignature)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, name, stream =>
    {
      Assert.IsTrue(DmgFile.Is(stream));
      return DmgFile.Parse(stream);
    });

    Assert.AreEqual(hasSignature, file.HasSignature());
  }
}