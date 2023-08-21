using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Dmg;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
{
  // @formatter:off
    [TestCase("steam.dmg")]
    [TestCase("steam_not_signed.dmg")]
    [TestCase("json-viewer.dmg")]
  // @formatter:on
  [Test]
  public void Test(string name)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, name, stream =>
    {
      Assert.IsTrue(DmgFile.Is(stream));
      return true;
    });
  }
}