using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class PeSignatureVerifierTests
  {
    private const string pe_01_signed = "ServiceModelRegUI.dll";
    private const string pe_01_not_signed = "ServiceModelRegUI_no_sign.dll";
    private const string pe_01_trimmed_sign = "ServiceModelRegUI_trimmed_sign.dll";
    private const string pe_01_empty_sign = "ServiceModelRegUI_empty_sign.dll";
    private const string pe_01_broken_hash = "ServiceModelRegUI_broken_hash.dll";
    private const string pe_01_sha1 = "D64EC6AEC642441554E7CBA0E0513E35683C87AE";
    private const string pe_01_broken_sign = "ServiceModelRegUI_broken_sign.dll";
    private const string pe_01_broken_counter_sign = "ServiceModelRegUI_broken_counter_sign.dll";
    private const string pe_01_broken_nested_sign = "ServiceModelRegUI_broken_nested_sign.dll";
    private const string pe_01_broken_nested_sign_timestamp = "ServiceModelRegUI_broken_nested_sign_timestamp.dll";
    private const string pe_01_sha256 = "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A";
    private const string ms_codesign_roots = "ms_codesign_roots.p7b";
    private const string ms_timestamp_root = "ms_timestamp_root.p7b";

    private const string pe_02_empty_sign = "uninst.exe";
    private const string pe_02_sha1 = "58AA2C6CF6A446426F3596F1BC4AB4E1FAAC297A";

    private const string pe_03_signed = "shell32.dll";
    private const string pe_03_sha256 = "BB79CC7089BF061ED707FFB3FFA4ADE1DDAED0396878CC92D54A0E20A3C81619";

    private const string pe_04_signed = "IntelAudioService.exe";
    private const string pe_04_sha256 = "160F2FE667A9252AB5B2E01749CD40B024E749B10B49AD276345875BA073A57E";

    private const string pe_05_signed = "libcrypto-1_1-x64.dll";
    private const string pe_06_signed = "libssl-1_1-x64.dll";
    private const string pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe";
    private const string jb_codesign_roots = "jb_codesign_roots.p7b";
    private const string jb_timestamp_roots = "jb_timestamp_roots.p7b";

    private const string pe_08_signed = "dotnet.exe";
    private const string pe_09_broken_timestamp = "dotnet_broken_timestamp.exe";

    [TestCase(pe_01_signed, VerifySignatureStatus.Valid)]
    [TestCase(pe_01_broken_hash, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_01_broken_sign, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_01_broken_counter_sign, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_01_broken_nested_sign, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_01_broken_nested_sign_timestamp, VerifySignatureStatus.InvalidTimestamp)]
    [TestCase(pe_03_signed, VerifySignatureStatus.Valid)]
    [TestCase(pe_04_signed, VerifySignatureStatus.Valid)]
    [TestCase(pe_05_signed, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_06_signed, VerifySignatureStatus.InvalidSignature)]
    [TestCase(pe_07_signed, VerifySignatureStatus.Valid)]
    [TestCase(pe_09_broken_timestamp, VerifySignatureStatus.InvalidTimestamp)]
    public async Task VerifySignTest(string peResourceName, VerifySignatureStatus expectedResult)
    {
      var result = await Utils.StreamFromResource(peResourceName,
        async peFileStream =>
        {
          var verificationParams = new SignatureVerificationParams(null, null, false, false);
          var peFile = new PeFile(peFileStream);
          var signatureData = peFile.GetSignatureData();
          var signedMessage = SignedMessage.CreateInstance(signatureData);
          var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
          return await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
        });

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(pe_01_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root)]
    [TestCase(pe_07_signed, VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots)]
    [TestCase(pe_08_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root)]
    public async Task VerifySignWithChainTest(string peResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName)
    {
      var result = await Utils.StreamFromResource(peResourceName,
        peFileStream =>
          Utils.StreamFromResource(codesignRootCertStoreResourceName,
            codesignroots =>
              Utils.StreamFromResource(timestampRootCertStoreResourceName, timestamproots =>
              {
                var verificationParams = new SignatureVerificationParams(
                  codesignroots,
                  timestamproots,
                  buildChain: true,
                  withRevocationCheck: false);

                var peFile = new PeFile(peFileStream);
                var signatureData = peFile.GetSignatureData();
                var signedMessage = SignedMessage.CreateInstance(signatureData);
                var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
                return signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
              })));

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)]
    public async Task VerifySignWithChainTestInPast(string peResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.MinValue);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)]
    public async Task VerifySignWithChainTestInPresent(string peResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.Now);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)]
    public async Task VerifySignWithChainTestInFuture(string peResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        DateTime.MaxValue);

      Assert.AreEqual(expectedResult, actual.Status);
    }

    [TestCase(pe_01_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root)]
    public async Task VerifySignWithChainTestAboutSignTime(string peResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName)
    {
      var actual = await VerifySignWithChainTestInTime(peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        new DateTime(2019, 11, 24));

      Assert.AreEqual(expectedResult, actual.Status);
    }

    private Task<VerifySignatureResult> VerifySignWithChainTestInTime(string peResourceName,
      string codesignRootCertStoreResourceName,
      string timestampRootCertStoreResourceName,
      DateTime time)
    {
      return Utils.StreamFromResource(peResourceName,
        peFileStream =>
          Utils.StreamFromResource(codesignRootCertStoreResourceName,
            codesignroots =>
              Utils.StreamFromResource(timestampRootCertStoreResourceName, timestamproots =>
              {
                var verificationParams = new SignatureVerificationParams(
                  codesignroots,
                  timestamproots,
                  buildChain: true,
                  withRevocationCheck: false,
                  ocspResponseTimeout: null,
                  SignatureValidationTimeMode.SignValidationTime,
                  signatureValidationTime: time);

                var peFile = new PeFile(peFileStream);
                var signatureData = peFile.GetSignatureData();
                var signedMessage = SignedMessage.CreateInstance(signatureData);
                var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
                return signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
              })));
    }

    [TestCase(pe_01_signed, "SHA1", pe_01_sha1)]
    [TestCase(pe_01_not_signed, "SHA1", pe_01_sha1)]
    [TestCase(pe_01_signed, "SHA256", pe_01_sha256)]
    [TestCase(pe_01_not_signed, "SHA256", pe_01_sha256)]
    [TestCase(pe_01_trimmed_sign, "SHA1", pe_01_sha1)]
    [TestCase(pe_01_empty_sign, "SHA1", pe_01_sha1)]
    [TestCase(pe_02_empty_sign, "SHA1", pe_02_sha1)]
    [TestCase(pe_03_signed, "SHA256", pe_03_sha256)]
    [TestCase(pe_04_signed, "SHA256", pe_04_sha256)]
    public void ComputeHashTest(string peResourceName, string alg, string expectedResult)
    {
      var result = Utils.StreamFromResource(peResourceName,
        peFileStream => new PeFile(peFileStream).ComputeHash(alg));

      Assert.AreEqual(expectedResult, Utils.ConvertToHexString(result));
    }

    [TestCase(pe_01_signed, false)]
    [TestCase(pe_04_signed, true)]
    public void IsDotNetTest(string peResourceName, bool expectedResult)
    {
      var result = Utils.StreamFromResource(peResourceName,
        peFileStream => new PeFile(peFileStream).IsDotNet);

      Assert.AreEqual(expectedResult, result);
    }
  }
}