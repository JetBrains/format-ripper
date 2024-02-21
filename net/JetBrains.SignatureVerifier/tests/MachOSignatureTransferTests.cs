using System.IO;
using System.Threading.Tasks;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
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
  public async Task SignatureShouldBeTransfered(string donor, string acceptor)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.MachO, donor, stream => MachOFile.Parse(stream, MachOFile.Mode.SignatureData | MachOFile.Mode.ComputeHashInfo));

    Assert.NotNull(file.Signature);

    using MemoryStream resultFileStream = new MemoryStream();

    ResourceUtil.OpenRead(ResourceCategory.MachO, acceptor, stream =>
    {
      MachOSignatureInjector.InjectSignature(stream, resultFileStream, file.Signature);
      return 0;
    });

    MachOFile acceptorFile = MachOFile.Parse(resultFileStream, MachOFile.Mode.SignatureData | MachOFile.Mode.ComputeHashInfo);

    var verificationParams = new SignatureVerificationParams(null, null, false, false);

    MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

    var result =  await signatureVerifier.VerifyAsync(acceptorFile, resultFileStream, verificationParams, FileIntegrityVerificationParams.Default);

    Assert.AreEqual(VerifySignatureStatus.Valid, result.Status, "Signature verification failure");

    byte[] signedFileArray = ResourceUtil.OpenRead(ResourceCategory.MachO, donor, stream =>
    {
      byte[] data = new byte[stream.Length];
      stream.Read(data, 0, data.Length);
      return data;
    });

    byte[] acceptorFileArray = resultFileStream.ToArray();

    Assert.AreEqual(signedFileArray.Length, acceptorFileArray.Length, "Length equality failure");
    Assert.True(Arrays.AreEqual(signedFileArray, acceptorFileArray), "Byte equality failure");
  }
}