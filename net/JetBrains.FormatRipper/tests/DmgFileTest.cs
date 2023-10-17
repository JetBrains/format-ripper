using System;
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
  private static object?[] MakeSource(string resourceName, bool hasSignature, string hexDataChecksum,
    string hexMasterChecksum) =>
    new object?[] { resourceName, hasSignature, hexDataChecksum, hexMasterChecksum };

  [SuppressMessage("ReSharper", "InconsistentNaming")]
  private static readonly object?[] Sources =
  {
    MakeSource("json-viewer.dmg", true,
      "D995499000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "2B57903800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ),
    MakeSource("steam.dmg", true,
      "5B30E61D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "1DC16C5100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ),
    MakeSource("steam_not_signed.dmg", false,
      "5B30E61D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "1DC16C5100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
  };

  [TestCaseSource(typeof(DmgFileTest), nameof(Sources))]
  [Test]
  public unsafe void Test(string name, bool hasSignature, string hexDataChecksum, string hexMasterChecksum)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, name, stream =>
    {
      Assert.IsTrue(DmgFile.Is(stream));
      return DmgFile.Parse(stream);
    });

    byte[] dataChecksum = new byte[32 * sizeof(UInt32)];
    for (int i = 0; i < 32; i++)
    {
      byte[] bytes = BitConverter.GetBytes(file.DataChecksum.data[i]);
      for (int j = 0; j < bytes.Length; j++)
      {
        dataChecksum[i * sizeof(UInt32) + j] = bytes[j];
      }
    }

    byte[] masterChecksum = new byte[32 * sizeof(UInt32)];
    for (int i = 0; i < 32; i++)
    {
      byte[] bytes = BitConverter.GetBytes(file.MasterChecksum.data[i]);
      for (int j = 0; j < bytes.Length; j++)
      {
        masterChecksum[i * sizeof(UInt32) + j] = bytes[j];
      }
    }

    Assert.AreEqual(HexUtil.ConvertToHexString(dataChecksum), hexDataChecksum);
    Assert.AreEqual(HexUtil.ConvertToHexString(masterChecksum), hexMasterChecksum);
    Assert.AreEqual(hasSignature, file.HasSignature);
  }
}