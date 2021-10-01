using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.SignatureVerifier.Macho;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MachoSignatureVerifierTests
  {
    private const string apple_root = "apple_root.p7b";

    [TestCase("fat.dylib", VerifySignatureStatus.NotSigned)]
    [TestCase("x64.dylib", VerifySignatureStatus.NotSigned)]
    [TestCase("x86.dylib", VerifySignatureStatus.NotSigned)]
    [TestCase("fat.bundle", VerifySignatureStatus.NotSigned)]
    [TestCase("x64.bundle", VerifySignatureStatus.NotSigned)]
    [TestCase("x86.bundle", VerifySignatureStatus.NotSigned)]
    [TestCase("libSystem.Net.Security.Native.dylib", VerifySignatureStatus.InvalidSignature)]
    [TestCase("env-wrapper.x64", VerifySignatureStatus.Valid)]
    [TestCase("libMonoSupportW.x64.dylib", VerifySignatureStatus.Valid)]
    [TestCase("cat", VerifySignatureStatus.Valid)]
    public async Task VerifySignTest(string machoResourceName, VerifySignatureStatus expectedResult)
    {
      var machoFiles = Utils.StreamFromResource(machoResourceName,
        machoFileStream => new MachoArch(machoFileStream, ConsoleLogger.Instance).Extract());

      var p = new SignatureVerificationParams(
        signRootCertStore: null,
        timestampRootCertStore: null,
        buildChain: false,
        withRevocationCheck: false);

      foreach (MachoFile machoFile in machoFiles)
      {
        var result = await machoFile.VerifySignatureAsync(p);
        Assert.AreEqual(expectedResult, result.Status);
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
          var p = new SignatureVerificationParams(
            codesignroots,
            timestampRootCertStore: null,
            buildChain: true,
            withRevocationCheck: false);

          return machoFiles.Select(async machoFile => await machoFile.VerifySignatureAsync(p))
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