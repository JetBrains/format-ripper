using System.Linq;
using System.Security.Cryptography;
using JetBrains.FormatRipper.MachO;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [TestFixture]
  public class MachOComputeHashTest
  {
    // @formatter:off
    [TestCase("addhoc"           , "SHA1", "B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")]
    [TestCase("addhoc_resigned"  , "SHA1", "B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")]
    [TestCase("notsigned"        , "SHA1", "B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")]
    [TestCase("nosigned_resigned", "SHA1", "B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")]
    [TestCase("fat.dylib"        , "SHA1", "30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")]
    [TestCase("fat.dylib_signed" , "SHA1", "30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")]
    // @formatter:on
    [Test]
    public void Test(string resourceName, string hashAlgorithmName, params string[] expectedHashes)
    {
      var hashes = ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream => MachOFile.Parse(stream, MachOFile.Mode.ComputeHashInfo).Sections
        .Select(_ =>
          {
            Assert.IsNotNull(_.ComputeHashInfo);
            return HashUtil.ComputeHash(stream, _.ComputeHashInfo, new HashAlgorithmName(hashAlgorithmName));
          }).ToArray());
      Assert.AreEqual(expectedHashes.Length, hashes.Length);
      for (var index = 0; index < expectedHashes.Length; ++index)
        Assert.AreEqual(expectedHashes[index], HexUtil.ConvertToHexString(hashes[index]));
    }
  }
}