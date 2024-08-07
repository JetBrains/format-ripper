using System.IO;
using System.Threading.Tasks;
using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;
using Org.BouncyCastle.Utilities;

namespace JetBrains.SignatureVerifier.Tests;

public class DmgSignatureTransferTest
{
  [TestCase("license-signed.dmg", "license.dmg")]
  [TestCase("test-signed.dmg", "test.dmg")]
  [TestCase("test-readonly-signed.dmg", "test-readonly.dmg")]
  [TestCase("test2-signed.dmg", "test2.dmg")]
  [TestCase("test2-signed-timestamped.dmg", "test2.dmg")]
  [TestCase("test2-signed-timestamped.dmg", "test2-signed.dmg")]
  [TestCase("test2-signed.dmg", "test2-signed-timestamped.dmg")]
  public async Task SignatureShouldBeTransfered(string donor, string acceptor)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, donor, stream => DmgFile.Parse(stream, DmgFile.Mode.SignatureData));

    Assert.NotNull(file.SignatureTransferData);

    using MemoryStream resultFileStream = new MemoryStream();

    ResourceUtil.OpenRead(ResourceCategory.Dmg, acceptor, stream =>
    {
      DmgSignatureInjector.InjectSignature(stream, resultFileStream, file.SignatureTransferData);
      return 0;
    });

    DmgFile acceptorFile = DmgFile.Parse(resultFileStream, DmgFile.Mode.SignatureData);

    var verificationParams = new SignatureVerificationParams(null, null, false, false);

    DmgSignatureVerifier signatureVerifier = new DmgSignatureVerifier(ConsoleLogger.Instance);

    var result =  await signatureVerifier.VerifyAsync(acceptorFile, resultFileStream, verificationParams, FileIntegrityVerificationParams.Default);

    Assert.AreEqual(VerifySignatureStatus.Valid, result.Status, "Signature verification failure");

    byte[] signedFileArray = ResourceUtil.OpenRead(ResourceCategory.Dmg, donor, stream =>
    {
      byte[] data = new byte[stream.Length];
      stream.Read(data, 0, data.Length);
      return data;
    });

    byte[] acceptorFileArray = resultFileStream.ToArray();

    Assert.AreEqual(signedFileArray.Length, acceptorFileArray.Length, "Length equality failure");
    Assert.True(Arrays.AreEqual(signedFileArray, acceptorFileArray), "Byte equality failure");
  }

  [TestCase("test-signed.dmg", "test-readonly.dmg")]
  [TestCase("test-signed.dmg", "test2.dmg")]
  [TestCase("test2-signed.dmg", "test.dmg")]
  [TestCase("test-signed.dmg", "license.dmg")]
  [TestCase("license-signed.dmg", "test.dmg")]
  public void SignatureTransferBetweenIncompatibleFilesShouldThrowException(string donor, string acceptor)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Dmg, donor, stream => DmgFile.Parse(stream, DmgFile.Mode.SignatureData));

    Assert.NotNull(file.SignatureTransferData);

    using MemoryStream resultFileStream = new MemoryStream();

    ResourceUtil.OpenRead(ResourceCategory.Dmg, acceptor, stream =>
    {
      Assert.Throws<SignatureInjectionException>(() => DmgSignatureInjector.InjectSignature(stream, resultFileStream, file.SignatureTransferData));
      return 0;
    });
  }
}