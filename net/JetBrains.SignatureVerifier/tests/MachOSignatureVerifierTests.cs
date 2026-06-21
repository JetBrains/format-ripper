using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.Tests;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MachOSignatureVerifierTests
  {
    private const string apple_root = "apple_root.p7b";

    [TestCase(VerifySignatureStatus.Valid, "JetBrains.Profiler.PdbServer")]
    [TestCase(VerifySignatureStatus.Valid, "cat")]
    [TestCase(VerifySignatureStatus.Valid, "env-wrapper.x64")]
    [TestCase(VerifySignatureStatus.Valid, "libMonoSupportW.x64.dylib")]
    [TestCase(VerifySignatureStatus.Valid, "libhostfxr.dylib")]
    [TestCase(VerifySignatureStatus.Valid, "draw.io-7.6.6")]
    [TestCase(VerifySignatureStatus.Valid, "draw.io-13.9.9")]
    [TestCase(VerifySignatureStatus.Valid, "draw.io-14.1.8")]
    [TestCase(VerifySignatureStatus.Valid, "draw.io-22.1.2")]
    [TestCase(VerifySignatureStatus.Valid, "libquit.dylib")]
    [TestCase(VerifySignatureStatus.Valid, "libapple_crypto.dylib")]
    [TestCase(VerifySignatureStatus.Valid, "libspindump.dylib")]
    [TestCase(VerifySignatureStatus.InvalidFileHash, "draw.io-13.9.9-edited")]
    [TestCase(VerifySignatureStatus.InvalidSignature, "TestCppApp2_adhoc")]
    public async Task VerifySignTest(VerifySignatureStatus expectedResult, string machoResourceName)
    {
      var verificationParams = new SignatureVerificationParams(buildChain: false, withRevocationCheck: false);

      var result = await TestDataUtil.OpenRead(ResourceCategory.MachO, machoResourceName, stream =>
      {
        MachOFile machOFile = MachOFile.Parse(stream);
        MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

        return signatureVerifier.VerifyAsync(machOFile, stream, verificationParams, FileIntegrityVerificationParams.Default);
      });

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(VerifySignatureStatus.Valid, "libspindump.dylib")]
    [TestCase(VerifySignatureStatus.InvalidFileHash, "draw.io-13.9.9-edited")]
    [TestCase(VerifySignatureStatus.Valid, "TestCppApp2_adhoc")]
    public async Task VerifySignAdhocTest(VerifySignatureStatus expectedResult, string machoResourceName)
    {
      var verificationParams = new SignatureVerificationParams(buildChain: false, withRevocationCheck: false, allowAdhocSignatures: true);

      var result = await TestDataUtil.OpenRead(ResourceCategory.MachO, machoResourceName, stream =>
      {
        MachOFile machOFile = MachOFile.Parse(stream);
        MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

        return signatureVerifier.VerifyAsync(machOFile, stream, verificationParams, FileIntegrityVerificationParams.Default);
      });

      Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase("libSystem.Net.Security.Native.dylib")]
    public void VerifySignInvalidSignatureFormat(string machoResourceName)
    {
      TestDataUtil.OpenRead(ResourceCategory.MachO, machoResourceName, stream =>
      {
        foreach (var section in MachOFile.Parse(stream).Sections)
        {
          var loadCommandsInfo = MachOUtil.ReadLoadCommands(section, MachOFile.Mode.SignatureData);
          Assert.That(() => SignedMessage.CreateInstance(loadCommandsInfo.SignatureData), Throws.Exception, "Invalid signature format");
        }
        return 0;
      });
    }

    [TestCase(VerifySignatureStatus.Valid, apple_root, "JetBrains.Profiler.PdbServer")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "cat")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "env-wrapper.x64")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libMonoSupportW.x64.dylib")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libhostfxr.dylib")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "draw.io-7.6.6")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "draw.io-13.9.9")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "draw.io-14.1.8")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "draw.io-22.1.2")]
    public void VerifySignWithChainTest(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string machOResourceName)
    {
      var results = TestDataUtil.OpenRead(ResourceCategory.MachO, codesignRootCertStoreResourceName, codeSignRootsStream =>
        {
          var verificationParams = new SignatureVerificationParams(codeSignRootsStream, withRevocationCheck: false);

          return TestDataUtil.OpenRead(ResourceCategory.MachO, machOResourceName, stream =>
          {
            MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

            return MachOFile.Parse(stream).Sections
              .Select(async section =>
              {
                return await signatureVerifier.VerifyAsync(section, stream, verificationParams, FileIntegrityVerificationParams.Default);
              })
              .Select(_ => _.Result)
              .ToList();
          });
        });

      foreach (VerifySignatureResult result in results)
        Assert.AreEqual(expectedResult, result.Status);
    }

    [TestCase(VerifySignatureStatus.Valid, apple_root, "libquit.dylib", "2020-1-1")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libapple_crypto.dylib", "2020-1-1")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libspindump.dylib", "2020-1-1")]
    public void VerifySignWithChainAndExactValidationTimeTest(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string machOResourceName,
      DateTime validationTime)
    {
      var results = TestDataUtil.OpenRead(ResourceCategory.MachO, codesignRootCertStoreResourceName, codeSignRootsStream =>
        {
          var verificationParams = new SignatureVerificationParams(
            codeSignRootsStream,
            withRevocationCheck: false,
            signatureValidationTimeMode: SignatureValidationTimeMode.SignValidationTime,
            signatureValidationTime: validationTime);

          return TestDataUtil.OpenRead(ResourceCategory.MachO, machOResourceName, stream =>
          {
            MachOSignatureVerifier signatureVerifier = new MachOSignatureVerifier(ConsoleLogger.Instance);

            return MachOFile.Parse(stream).Sections
              .Select(async section =>
              {
                return await signatureVerifier.VerifyAsync(section, stream, verificationParams, FileIntegrityVerificationParams.Default);
              })
              .Select(_ => _.Result)
              .ToList();
          });
        });

      foreach (VerifySignatureResult result in results)
        Assert.AreEqual(expectedResult, result.Status);
    }
  }
}