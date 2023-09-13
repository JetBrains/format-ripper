using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using JetBrains.FormatRipper.Compound;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MsiSignatureVerifierTests
  {
    // @formatter:off
    [TestCase(VerifySignatureStatus.Valid           , "2dac4b_signed2.msi")]
    [TestCase(VerifySignatureStatus.Valid           , "2dac4b.msi")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "2dac4b_broken_hash.msi")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "2dac4b_broken_sign.msi")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "2dac4b_broken_timestamp.msi")]
    // @formatter:on
    [Test]
    public async Task VerifySignTest(VerifySignatureStatus expectedResult, string resourceName)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Msi, resourceName, stream =>
      {
        Assert.IsTrue(CompoundFile.Is(stream));
        return CompoundFile.Parse(stream, CompoundFile.Mode.SIGNATURE_DATA);
      });

      var verificationParams = new SignatureVerificationParams(null, null, false, false);
      var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
      var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
      var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      Assert.AreEqual(expectedResult, result.Status);
    }
  }
}