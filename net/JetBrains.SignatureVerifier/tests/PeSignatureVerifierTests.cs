using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class PeSignatureVerifierTests
  {
    private const string ms_codesign_roots = "ms_codesign_roots.p7b";
    private const string ms_timestamp_root = "ms_timestamp_root.p7b";

    private const string jb_codesign_roots = "jb_codesign_roots.p7b";
    private const string jb_timestamp_roots = "jb_timestamp_roots.p7b";

    // @formatter:off
    [TestCase(VerifySignatureStatus.Valid           , "ServiceModelRegUI.dll")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "ServiceModelRegUI_broken_hash.dll")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "ServiceModelRegUI_broken_sign.dll")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "ServiceModelRegUI_broken_counter_sign.dll")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "ServiceModelRegUI_broken_nested_sign.dll")]
    [TestCase(VerifySignatureStatus.InvalidTimestamp, "ServiceModelRegUI_broken_nested_sign_timestamp.dll")]
    [TestCase(VerifySignatureStatus.Valid           , "shell32.dll")]
    [TestCase(VerifySignatureStatus.Valid           , "IntelAudioService.exe")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "libcrypto-1_1-x64.dll")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "libssl-1_1-x64.dll")]
    [TestCase(VerifySignatureStatus.Valid           , "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe")]
    [TestCase(VerifySignatureStatus.Valid           , "JetBrains.ReSharper.TestResources.dll")]
    [TestCase(VerifySignatureStatus.InvalidTimestamp, "dotnet_broken_timestamp.exe")]
    // @formatter:on
    public async Task VerifySignTest(VerifySignatureStatus expectedResult, string peResourceName)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Pe, peResourceName, stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

      var verificationParams = new SignatureVerificationParams(null, null, false, false);
      var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
      var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
      var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root, "ServiceModelRegUI.dll")]
    [TestCase(VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots, "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe")]
    [TestCase(VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots, "JetBrains.ReSharper.TestResources.dll")]
    [TestCase(VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root, "dotnet.exe")]
    public async Task VerifySignWithChainTest(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      string peResourceName)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Pe, peResourceName, stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

      var result = await ResourceUtil.OpenRead(ResourceCategory.Pe, codesignRootCertStoreResourceName, codeSignRootsStream =>
        ResourceUtil.OpenRead(ResourceCategory.Pe, timestampRootCertStoreResourceName, timeStampRootsStream =>
          {
            var verificationParams = new SignatureVerificationParams(
              codeSignRootsStream,
              timeStampRootsStream,
              buildChain: true,
              withRevocationCheck: false);

            var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
            var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
            return signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

          }));

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root, "ServiceModelRegUI.dll")]
    public async Task VerifySignWithChainTestInPast(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      string peResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.MinValue);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root, "ServiceModelRegUI.dll")]
    public async Task VerifySignWithChainTestInPresent(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      string peResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.Now);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root, "ServiceModelRegUI.dll")]
    public async Task VerifySignWithChainTestInFuture(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      string peResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.MaxValue);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root, "ServiceModelRegUI.dll")]
    public async Task VerifySignWithChainTestAboutSignTime(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      string peResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        new DateTime(2019, 11, 24));

      Assert.AreEqual(expectedResult, actual.Status);
    }

    private Task<VerifySignatureResult> VerifySignWithChainTestInTime(
      string peResourceName,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      DateTime time)
    {
      var file = ResourceUtil.OpenRead(ResourceCategory.Pe, peResourceName, stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

      return
        ResourceUtil.OpenRead(ResourceCategory.Pe, codesignRootCertStoreResourceName, codeSignRootsStream =>
          ResourceUtil.OpenRead(ResourceCategory.Pe, timestampRootCertStoreResourceName, timeStampRootsStream =>
            {
              var verificationParams = new SignatureVerificationParams(
                codeSignRootsStream,
                timeStampRootsStream,
                buildChain: true,
                withRevocationCheck: false,
                ocspResponseTimeout: null,
                SignatureValidationTimeMode.SignValidationTime,
                signatureValidationTime: time);

              var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
              var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
              return signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
            }));
    }
  }
}