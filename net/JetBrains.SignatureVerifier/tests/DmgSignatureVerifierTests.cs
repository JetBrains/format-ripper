using System.Security.Cryptography;
using System.Threading.Tasks;
using JetBrains.FormatRipper.Dmg;
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
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, DmgFile.Parse);

    var verificationParams = new SignatureVerificationParams(null, null, false, false);

    Assert.IsTrue(file.HasSignature());

    var signedMessage = SignedMessage.CreateInstance(file.SignatureData().Value);
    var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
    var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

    Assert.AreEqual(expectedResult, result.Status);
  }

  // @formatter:off
   [TestCase("steam.dmg", "SHA1", "02A79BE766434D8D5846840074B732F07B9991B6")]
   [TestCase("steam_not_signed.dmg", "SHA1", "02A79BE766434D8D5846840074B732F07B9991B6")]
   [TestCase("steam.dmg", "SHA256", "5BCD5694E10BB1EEDE33414D5A53A243687E524CA48420FCA03F3F0911732F77")]
   [TestCase("steam_not_signed.dmg", "SHA256", "5BCD5694E10BB1EEDE33414D5A53A243687E524CA48420FCA03F3F0911732F77")]
   [TestCase("json-viewer.dmg", "SHA1", "A4DD9A946EC0973C826FFE78E24E5CF2BCADA774")]
   [TestCase("json-viewer.dmg", "SHA256", "068878BE00AA22A4056A7976C414DB60D1D874804FDAC1549AB5F883D2C6968B")]
  // @formatter:on
  public void Test(string resourceName, string hashAlgorithmName, string expectedResult)
  {
    var result = ResourceUtil.OpenRead(ResourceCategory.Dmg, resourceName, stream =>
    {
      var file = DmgFile.Parse(stream);
      return HashUtil.ComputeHash(stream, file.ComputeHashInfo, new HashAlgorithmName(hashAlgorithmName));
    });
    Assert.AreEqual(expectedResult, HexUtil.ConvertToHexString(result));
  }
}