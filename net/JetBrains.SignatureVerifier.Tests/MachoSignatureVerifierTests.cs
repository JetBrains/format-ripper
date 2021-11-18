using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.SignatureVerifier.Macho;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests.Macho
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MachoSignatureVerifierTests
  {
    private const string apple_root = "apple_root.p7b";

    [TestCase("env-wrapper.x64", VerifySignatureStatus.Valid)]
    [TestCase("libMonoSupportW.x64.dylib", VerifySignatureStatus.Valid)]
    [TestCase("cat", VerifySignatureStatus.Valid)]
    public async Task VerifySignTest(string machoResourceName, VerifySignatureStatus expectedResult)
    {
      var machoFiles = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      var verificationParams = new SignatureVerificationParams(
        signRootCertStore: null,
        timestampRootCertStore: null,
        buildChain: false,
        withRevocationCheck: false);

      foreach (MachoFile machoFile in machoFiles)
      {
        var signatureData = machoFile.GetSignatureData();
        var signedMessage = SignedMessage.CreateInstance(signatureData);
        var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
        var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

        Assert.AreEqual(expectedResult, result.Status);
      }
    }

    [TestCase("libSystem.Net.Security.Native.dylib")]
    public void VerifySignInvalidSignatureFormat(string machoResourceName)
    {
      var machoFiles = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      foreach (MachoFile machoFile in machoFiles)
      {
        var signatureData = machoFile.GetSignatureData();
        Action action = () => SignedMessage.CreateInstance(signatureData);

        action.Should()
          .Throw<Exception>()
          .WithMessage("Invalid signature format");
      }
    }

    [TestCase("env-wrapper.x64", VerifySignatureStatus.Valid, apple_root)]
    [TestCase("libMonoSupportW.x64.dylib", VerifySignatureStatus.Valid, apple_root)]
    [TestCase("libhostfxr.dylib", VerifySignatureStatus.Valid, apple_root)]
    [TestCase("cat", VerifySignatureStatus.Valid, apple_root)]
    [TestCase("JetBrains.Profiler.PdbServer", VerifySignatureStatus.Valid, apple_root)]
    public void VerifySignWithChainTest(string machoResourceName,
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName)
    {
      var machoFiles = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      var results =
        Utils.StreamFromResource(codesignRootCertStoreResourceName, codesignroots =>
        {
          var verificationParams = new SignatureVerificationParams(
            codesignroots,
            timestampRootCertStore: null,
            buildChain: true,
            withRevocationCheck: false);

          return machoFiles.Select(async machoFile =>
            {
              var signatureData = machoFile.GetSignatureData();
              var signedMessage = SignedMessage.CreateInstance(signatureData);
              var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
              return await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
            })
            .Select(s => s.Result)
            .ToList();
        });

      foreach (VerifySignatureResult result in results)
      {
        Assert.AreEqual(expectedResult, result.Status);
      }
    }
  }
}