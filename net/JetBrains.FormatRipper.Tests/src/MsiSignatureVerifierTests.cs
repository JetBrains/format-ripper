using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using JetBrains.SignatureVerifier.Cf;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests.Msi
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MsiSignatureVerifierTests
  {
    private const string msi_01_signed = "2dac4b.msi";
    private const string msi_01_not_signed = "2dac4b_not_signed.msi";
    private const string msi_01_broken_hash = "2dac4b_broken_hash.msi";
    private const string msi_01_broken_sign = "2dac4b_broken_sign.msi";
    private const string msi_01_broken_timestamp = "2dac4b_broken_timestamp.msi";

    private const string msi_01_sha1 = "CBBE5C1017C8A65FFEB9219F465C949563A0E256";

    [TestCase(msi_01_signed, VerifySignatureStatus.Valid)]
    [TestCase(msi_01_broken_hash, VerifySignatureStatus.InvalidSignature)]
    [TestCase(msi_01_broken_sign, VerifySignatureStatus.InvalidSignature)]
    [TestCase(msi_01_broken_timestamp, VerifySignatureStatus.InvalidSignature)]
    public async Task VerifySignTest(string resourceName, VerifySignatureStatus expectedResult)
    {
      var result = await Utils.StreamFromResource(resourceName,
        async fileStream =>
        {
          var verificationParams = new SignatureVerificationParams(null, null, false, false);
          var msiFile = new MsiFile(fileStream);
          var signatureData = msiFile.GetSignatureData();
          var signedMessage = SignedMessage.CreateInstance(signatureData);
          var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
          return await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
        });

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(msi_01_signed, "SHA1", msi_01_sha1)]
    [TestCase(msi_01_not_signed, "SHA1", msi_01_sha1)]
    public void ComputeHashTest(string resourceName, string alg, string expectedResult)
    {
      var result = Utils.StreamFromResource(resourceName,
        fileStream => new MsiFile(fileStream).ComputeHash(alg, skipMsiDigitalSignatureExEntry: true));

      Assert.AreEqual(expectedResult, Utils.ConvertToHexString(result));
    }
  }
}