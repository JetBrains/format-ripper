using System.IO;
using System.Threading.Tasks;
using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;
using Org.BouncyCastle.Utilities;

namespace JetBrains.SignatureVerifier.Tests;

public class PeSignatureTransferTest
{
  [TestCase("HelloWorld1_signed.exe", "HelloWorld1.exe")]
  [TestCase("HelloWorld1_signed.exe", "HelloWorld1_extra_1_byte.exe")]
  [TestCase("HelloWorld1_realigned_signed.exe", "HelloWorld1_realigned.exe")]
  [TestCase("CSharpApp_signed.exe", "CSharpApp.exe")]
  [TestCase("TestCApp_signed.exe", "TestCApp.exe")]
  [TestCase("TestCApp_vs_signed.exe", "TestCApp_vs.exe")]
  [TestCase("HelloWorld3_signed.exe", "HelloWorld4.exe")]
  [TestCase("HelloWorld4_signed.exe", "HelloWorld3.exe")]
  [TestCase("HelloWorld3_signed.exe", "HelloWorld4_signed_timestamped.exe")]
  [TestCase("HelloWorld4_signed_timestamped.exe", "HelloWorld3_signed.exe")]
  public async Task SignatureShouldBeTransfered(string donor, string acceptor)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Pe, donor, stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

    Assert.NotNull(file.Signature);

    using MemoryStream acceptorFileStream = new MemoryStream();

    ResourceUtil.OpenRead(ResourceCategory.Pe, acceptor, stream =>
    {
      stream.CopyTo(acceptorFileStream);
      return 0;
    });

    PeSignatureInjector.InjectSignature(acceptorFileStream, file.Signature);

    PeFile acceptorFile = PeFile.Parse(acceptorFileStream, PeFile.Mode.SignatureData | PeFile.Mode.ComputeHashInfo);

    var verificationParams = new SignatureVerificationParams(null, null, false, false);
    var authenticodeSignatureVerifier = new AuthenticodeSignatureVerifier(ConsoleLogger.Instance);
    var result = await authenticodeSignatureVerifier.VerifyAsync(acceptorFile, acceptorFileStream, verificationParams, FileIntegrityVerificationParams.Default);

    Assert.AreEqual(VerifySignatureStatus.Valid, result.Status, "Signature verification failure");

    byte[] signedFileArray = ResourceUtil.OpenRead(ResourceCategory.Pe, donor, stream =>
    {
      byte[] data = new byte[stream.Length];
      stream.Read(data, 0, data.Length);
      return data;
    });

    byte[] acceptorFileArray = acceptorFileStream.ToArray();

    Assert.AreEqual(signedFileArray.Length, acceptorFileArray.Length, "Length equality failure");
    Assert.True(Arrays.AreEqual(signedFileArray, acceptorFileArray), "Byte equality failure");
  }

  [TestCase("HelloWorld1_signed.exe", "HelloWorld2.exe")]
  [TestCase("HelloWorld2_signed.exe", "HelloWorld1.exe")]
  public void SignatureTransferBetweenIncompatibleFilesShouldThrowException(string donor, string acceptor)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Pe, donor, stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

    Assert.NotNull(file.Signature);

    using MemoryStream acceptorFileStream = new MemoryStream();

    ResourceUtil.OpenRead(ResourceCategory.Pe, acceptor, stream =>
    {
      stream.CopyTo(acceptorFileStream);
      return 0;
    });

    Assert.Throws<SignatureInjectionException>(() => PeSignatureInjector.InjectSignature(acceptorFileStream, file.Signature));
  }
}