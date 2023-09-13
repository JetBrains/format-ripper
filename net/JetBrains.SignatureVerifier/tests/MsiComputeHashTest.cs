using System.Security.Cryptography;
using JetBrains.FormatRipper.Compound;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [TestFixture]
  public class MsiComputeHashTest
  {
    // @formatter:off
    [TestCase("2dac4b.msi"           , "SHA1", "CBBE5C1017C8A65FFEB9219F465C949563A0E256")]
    [TestCase("2dac4b_not_signed.msi", "SHA1", "CBBE5C1017C8A65FFEB9219F465C949563A0E256")]
    // @formatter:on
    [Test]
    public void ComputeHashTest(string resourceName, string hashAlgorithmName, string expectedHash)
    {
      var hash = ResourceUtil.OpenRead(ResourceCategory.Msi, resourceName, stream =>
        {
          var file = CompoundFile.Parse(stream, CompoundFile.Mode.COMPUTE_HASH_INFO);
          Assert.IsNotNull(file.ComputeHashInfo);
          return HashUtil.ComputeHash(stream, file.ComputeHashInfo, new HashAlgorithmName(hashAlgorithmName));
        });
      Assert.AreEqual(expectedHash, HexUtil.ConvertToHexString(hash));
    }
  }
}