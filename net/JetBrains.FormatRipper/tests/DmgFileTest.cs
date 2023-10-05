using System.Collections.Generic;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Dmg;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

public class DmgFileTest
{
  private struct BLKXEntry
  {
    public readonly string Attributes;
    public readonly string CFName;
    public readonly List<List<string>> CompressedBlocks;
    public readonly string ID;
    public readonly string Name;
  }

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

    Assert.AreEqual(hasSignature, file.HasSignature);
  }
}