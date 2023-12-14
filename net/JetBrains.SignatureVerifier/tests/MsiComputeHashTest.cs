using System.Security.Cryptography;
using JetBrains.FormatRipper.Compound;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [TestFixture]
  public class MsiComputeHashTest
  {
    // @formatter:off
    [TestCase("2dac4b.msi"           , "SHA1", "EB0D6F874462F8ACC60C07D0D7B5A9C847EE311A")]
    [TestCase("2dac4b_not_signed.msi", "SHA1", "CBBE5C1017C8A65FFEB9219F465C949563A0E256")]
    [TestCase("2dac4b_self_signed.msi", "SHA256", "A930749F40001E6CBE1656720E4951CD8C70843BD4E1326EDE2402392E952025")]
    // @formatter:on
    [Test]
    public void ComputeHashTest(string resourceName, string hashAlgorithmName, string expectedHash)
    {
      var hash = ResourceUtil.OpenRead(ResourceCategory.Msi, resourceName, stream =>
        {
          var file = CompoundFile.Parse(stream, CompoundFile.Mode.ComputeHashInfo);
          Assert.IsNotNull(file.ComputeHashInfo);
          return HashUtil.ComputeHash(stream, file.ComputeHashInfo, new HashAlgorithmName(hashAlgorithmName));
        });
      var fileHash = HexUtil.ConvertToHexString(hash);
      Assert.AreEqual(expectedHash, fileHash);
    }
  }
}