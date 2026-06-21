using System.IO;
using System.Threading.Tasks;
using JetBrains.FormatRipper;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.Tests;
using NUnit.Framework;
using Org.BouncyCastle.Utilities;

namespace JetBrains.SignatureVerifier.Tests;

public class MachOSignatureTransferTests
{
  [TestCase("TestCppApp1_signed", "TestCppApp1")]
  [TestCase("TestCppApp1_signed", "TestCppApp1_signed_removed")]
  [TestCase("TestCppApp2_adhoc_signed", "TestCppApp2_adhoc")]
  [TestCase("TestApp_developer", "TestApp_adhoc")]
  [TestCase("TestApp_developer", "TestApp_not_signed")]
  [TestCase("cat", "cat_removed_signature")]
  [TestCase("FatTestCppApp_signed", "FatTestCppApp")]
  [TestCase("FatTestCppApp_adhoc_signed", "FatTestCppApp_adhoc")]
  [TestCase("FatTestCppApp_signed_timestamped", "FatTestCppApp_signed")]
  [TestCase("FatTestCppApp_signed", "FatTestCppApp_signed_timestamped")]
  [TestCase("TestCppApp2_adhoc", "TestCppApp2_adhoc_signed")]
  public async Task SignatureShouldBeTransfered(string donor, string acceptor)
  {
    var signature = TestDataUtil.OpenRead(ResourceCategory.MachO, donor, stream =>
    {
      var file = MachOFile.Parse(stream);
      return MachOUtil.ReadSignatureTransferData(file, MachOFile.Mode.SignatureData);
    });

    Assert.NotNull(signature);

    using MemoryStream resultFileStream = new MemoryStream();

    TestDataUtil.OpenRead(ResourceCategory.MachO, acceptor, stream =>
    {
      MachOSignatureInjector.InjectSignature(stream, resultFileStream, signature);
      return 0;
    });

    MachOFile acceptorFile = MachOFile.Parse(resultFileStream);

    var verificationParams = new SignatureVerificationParams(null, null, false, false, allowAdhocSignatures: true);

    MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

    var result =  await signatureVerifier.VerifyAsync(acceptorFile, resultFileStream, verificationParams, FileIntegrityVerificationParams.Default);

    Assert.AreEqual(VerifySignatureStatus.Valid, result.Status, "Signature verification failure");

    byte[] signedFileArray = TestDataUtil.OpenRead(ResourceCategory.MachO, donor, stream =>
    {
      using MemoryStream data = new MemoryStream();
      stream.CopyTo(data);
      return data.ToArray();
    });

    byte[] acceptorFileArray = resultFileStream.ToArray();

    Assert.AreEqual(signedFileArray.Length, acceptorFileArray.Length, "Length equality failure");
    Assert.True(Arrays.AreEqual(signedFileArray, acceptorFileArray), "Byte equality failure");
  }

  [TestCase("FatTestCppApp_signed", "TestCppApp1")]
  [TestCase("TestCppApp1_signed", "FatTestCppApp_signed")]
  [TestCase("cat", "FatTestCppApp")]
  [TestCase("FatTestCppApp_signed", "cat_removed_signature")]
  [TestCase("TestCppApp1_signed", "TestApp_adhoc")]
  [TestCase("TestApp_developer", "TestCppApp1")]
  public void SignatureTransferBetweenIncompatibleFilesShouldThrowException(string donor, string acceptor)
  {
    var signature = TestDataUtil.OpenRead(ResourceCategory.MachO, donor, stream =>
    {
      var file = MachOFile.Parse(stream);
      return MachOUtil.ReadSignatureTransferData(file, MachOFile.Mode.SignatureData);
    });

    Assert.NotNull(signature);

    using MemoryStream resultFileStream = new MemoryStream();

    TestDataUtil.OpenRead(ResourceCategory.MachO, acceptor, stream =>
    {
      Assert.Throws<SignatureInjectionException>(() => MachOSignatureInjector.InjectSignature(stream, resultFileStream, signature));
      return 0;
    });
  }
}