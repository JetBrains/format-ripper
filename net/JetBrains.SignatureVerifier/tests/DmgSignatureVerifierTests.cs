using System.Threading.Tasks;
using JetBrains.FormatRipper.Dmg;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests;

public class DmgSignatureVerifierTests
{
  private static DmgFile GetDmgFile(string resourceName) => ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, stream => DmgFile.Parse(stream, DmgFile.Mode.SignatureData | DmgFile.Mode.ComputeHashInfo));

  // @formatter:off
  [TestCase(VerifySignatureStatus.Valid,            "license-signed.dmg")]
  [TestCase(VerifySignatureStatus.Valid,            "test-signed.dmg")]
  [TestCase(VerifySignatureStatus.Valid,            "test-readonly-signed.dmg")]
  [TestCase(VerifySignatureStatus.InvalidFileHash,  "test-signed-edited.dmg")]
  [TestCase(VerifySignatureStatus.InvalidSignature, "test-signed-invalid-signature.dmg")]
  [TestCase(VerifySignatureStatus.InvalidSignature, "test.dmg")]
  // @formatter:oт
  public async Task VerifyDmgAsync(VerifySignatureStatus expectedResult, string resourceName)
  {
    var verificationParams = new SignatureVerificationParams(buildChain: false, withRevocationCheck: false);

    DmgFile dmgFile = GetDmgFile(resourceName);

    var result = await ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, stream =>
    {
      DmgSignatureVerifier signatureVerifier = new DmgSignatureVerifier(ConsoleLogger.Instance);

      return signatureVerifier.VerifyAsync(dmgFile, stream, verificationParams, FileIntegrityVerificationParams.Default);
    });

    Assert.AreEqual(expectedResult, result.Status);
  }
}