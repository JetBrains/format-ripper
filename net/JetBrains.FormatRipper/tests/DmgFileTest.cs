using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Dmg;
using NUnit.Framework;

namespace JetBrains.FormatRipper.Tests;

[TestFixture]
public class DmgFileTest
{
  private static object?[] MakeSource(string resourceName, bool hasSignature) =>
    new object?[] { resourceName, hasSignature };

  [SuppressMessage("ReSharper", "InconsistentNaming")]
  private static readonly object?[] Sources =
  {
    MakeSource("json-viewer.dmg", true
    ),
    MakeSource("steam.dmg", true
    ),
    MakeSource("steam_not_signed.dmg", false
    )
  };

  [TestCaseSource(typeof(DmgFileTest), nameof(Sources))]
  [Test]
  public unsafe void Test(string name, bool hasSignature)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, name, stream =>
    {
      Assert.IsTrue(DmgFile.Is(stream));
      return DmgFile.Parse(stream);
    });

    Assert.AreEqual(hasSignature, file.HasSignature);
  }
}