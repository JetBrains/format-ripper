using JetBrains.SignatureExtractor;

namespace JetBrains.SignatureExtractor.Tests;

public class SignatureTransferTests
{
  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"          , "TestCppApp1")]
  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"          , "TestCppApp1_signed")]
  [TestCase(ResourceCategory.MachO, "TestApp_developer"           , "TestApp_adhoc")]
  [TestCase(ResourceCategory.MachO, "FatTestCppApp_signed"        , "FatTestCppApp")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld3_signed.exe"      , "HelloWorld4.exe")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld4_signed.exe"      , "HelloWorld3.exe")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld3_signed.exe"      , "HelloWorld4_signed_timestamped.exe")]
  [TestCase(ResourceCategory.Dmg  , "test2-signed-timestamped.dmg", "test2.dmg")]
  [TestCase(ResourceCategory.Dmg  , "test2-signed-timestamped.dmg", "test2-signed.dmg")]
  [TestCase(ResourceCategory.Dmg  , "test2-signed.dmg"            , "test2-signed-timestamped.dmg")]
  public void SignatureShouldBeTransfered(ResourceCategory resourceCategory, string donor, string acceptor)
  {
    using var donorFile = ResourceUtil.OpenRead(resourceCategory, donor);

    using MemoryStream signature = new MemoryStream();

    Assert.DoesNotThrowAsync(async () => await SignatureOperations.ExtractSignature(donorFile, signature));

    Assert.NotZero(signature.Length, "Extracted signature is empty");

    signature.Seek(0, SeekOrigin.Begin);

    using var acceptorFile = ResourceUtil.OpenRead(resourceCategory, acceptor);

    MemoryStream destinationFile = new MemoryStream();

    Assert.DoesNotThrowAsync(async () => await SignatureOperations.ApplySignature(acceptorFile, signature, destinationFile, true));
  }

  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"    , "TestApp_adhoc")]
  [TestCase(ResourceCategory.MachO, "TestApp_developer"     , "TestCppApp1")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld1_signed.exe", "HelloWorld2.exe")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld2_signed.exe", "HelloWorld1.exe")]
  [TestCase(ResourceCategory.Dmg  , "test-signed.dmg"       , "test2.dmg")]
  [TestCase(ResourceCategory.Dmg  , "test2-signed.dmg"      , "test.dmg")]
  public void SignatureShouldNotBeTransferedBetweenDifferentFiles(ResourceCategory resourceCategory, string donor, string acceptor)
  {
    using var donorFile = ResourceUtil.OpenRead(resourceCategory, donor);

    using MemoryStream signature = new MemoryStream();

    Assert.DoesNotThrowAsync(async () => await SignatureOperations.ExtractSignature(donorFile, signature));

    Assert.NotZero(signature.Length, "Extracted signature is empty");

    signature.Seek(0, SeekOrigin.Begin);

    using var acceptorFile = ResourceUtil.OpenRead(resourceCategory, acceptor);

    MemoryStream destinationFile = new MemoryStream();

    Assert.ThrowsAsync<JetBrains.FormatRipper.SignatureInjectionException>(async () => await SignatureOperations.ApplySignature(acceptorFile, signature, destinationFile, true));
  }

  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"    , ResourceCategory.Pe   , "HelloWorld1_signed.exe")]
  [TestCase(ResourceCategory.MachO, "TestApp_developer"     , ResourceCategory.Dmg  , "test-signed.dmg")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld1_signed.exe", ResourceCategory.MachO, "TestCppApp1_signed")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld2_signed.exe", ResourceCategory.Dmg  , "test2-signed.dmg")]
  [TestCase(ResourceCategory.Dmg  , "test-signed.dmg"       , ResourceCategory.MachO, "TestCppApp1_signed")]
  [TestCase(ResourceCategory.Dmg  , "test2-signed.dmg"      , ResourceCategory.Pe   , "HelloWorld2_signed.exe")]
  public void SignatureShouldNotBeTransferedBetweenIncompatibleFiles(ResourceCategory donorResourceCategory, string donor, ResourceCategory acceptorResourceCategory, string acceptor)
  {
    using var donorFile = ResourceUtil.OpenRead(donorResourceCategory, donor);

    using MemoryStream signature = new MemoryStream();

    Assert.DoesNotThrowAsync(async () => await SignatureOperations.ExtractSignature(donorFile, signature));

    Assert.NotZero(signature.Length, "Extracted signature is empty");

    signature.Seek(0, SeekOrigin.Begin);

    using var acceptorFile = ResourceUtil.OpenRead(acceptorResourceCategory, acceptor);

    MemoryStream destinationFile = new MemoryStream();

    Assert.ThrowsAsync<SignatureApplicationException>(async () => await SignatureOperations.ApplySignature(acceptorFile, signature, destinationFile, true));
  }

  [TestCase(ResourceCategory.MachO, "TestApp_not_signed")]
  [TestCase(ResourceCategory.Pe   , "HelloWorld1.exe")]
  [TestCase(ResourceCategory.Dmg  , "test.dmg")]
  public void SignatureExtractionShouldFailOnUnsignedFiles(ResourceCategory donorResourceCategory, string donor)
  {
    using var donorFile = ResourceUtil.OpenRead(donorResourceCategory, donor);

    MemoryStream signature = new MemoryStream();

    Assert.ThrowsAsync<SignatureExtractionException>(async () => await SignatureOperations.ExtractSignature(donorFile, signature));

    Assert.Zero(signature.Length, "Extracted signature is empty");
  }

  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"    , "TestCppApp1_edited"    , true , false)]
  [TestCase(ResourceCategory.MachO, "TestCppApp1_signed"    , "TestCppApp1_edited"    , false, true)]
  [TestCase(ResourceCategory.Pe   , "HelloWorld1_signed.exe", "HelloWorld1_edited.exe", false, true)]
  [TestCase(ResourceCategory.Pe   , "HelloWorld1_signed.exe", "HelloWorld1_edited.exe", true , false)]
  [TestCase(ResourceCategory.Dmg  , "test-signed.dmg"       , "test-signed-edited.dmg", true , false)]
  [TestCase(ResourceCategory.Dmg  , "test-signed.dmg"       , "test-signed-edited.dmg", false, true)]
  public void SignatureShouldBeTransferedWithoutVerification(ResourceCategory resourceCategory, string donor, string acceptor, bool verifySignature, bool expectSuccess)
  {
    using var donorFile = ResourceUtil.OpenRead(resourceCategory, donor);

    using MemoryStream signature = new MemoryStream();

    Assert.DoesNotThrowAsync(async () => await SignatureOperations.ExtractSignature(donorFile, signature));

    Assert.NotZero(signature.Length, "Extracted signature is empty");

    signature.Seek(0, SeekOrigin.Begin);

    using var acceptorFile = ResourceUtil.OpenRead(resourceCategory, acceptor);

    MemoryStream destinationFile = new MemoryStream();

    if (expectSuccess)
      Assert.DoesNotThrowAsync(async () => await SignatureOperations.ApplySignature(acceptorFile, signature, destinationFile, verifySignature));
    else
      Assert.ThrowsAsync<SignatureApplicationException>(async () => await SignatureOperations.ApplySignature(acceptorFile, signature, destinationFile, verifySignature));
  }
}