using System.Threading.Tasks;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests;

public class DmgSignatureVerifierTests
{
  // @formatter:off
    [TestCase(VerifySignatureStatus.Valid           , "steam.dmg")]
    [TestCase(VerifySignatureStatus.Valid           , "json-viewer.dmg")]
  // @formatter:on
  public async Task VerifySignTest(VerifySignatureStatus expectedResult, string resourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, stream => DmgFile.Parse(stream));

    var verificationParams = new SignatureVerificationParams(null, null, false, false);

    Assert.IsTrue(file.HasSignature());

    var signedMessage = SignedMessage.CreateInstance(file.SignatureData.Value);
    var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
    var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

    Assert.AreEqual(expectedResult, result.Status);
  }
}