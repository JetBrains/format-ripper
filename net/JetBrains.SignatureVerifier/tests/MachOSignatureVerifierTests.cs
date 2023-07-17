using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;

namespace JetBrains.SignatureVerifier.Tests
{
  public static class Extension
  {
    public static string ToHexString(this byte[] bytes)
    {
      var hexChars = "0123456789ABCDEF";
      var result = new StringBuilder(bytes.Length * 2);

      foreach (var b in bytes)
      {
        var value = b & 0xFF;
        result.Append(hexChars[value >> 4]);
        result.Append(hexChars[value & 0x0F]);
      }

      return result.ToString();
    }
  }

  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class MachOSignatureVerifierTests
  {
    private const string apple_root = "apple_root.p7b";

    private static MachOFile GetMachOFile(string resourceName) => ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName, stream => MachOFile.Parse(stream, MachOFile.Mode.SignatureData));

    [TestCase(VerifySignatureStatus.Valid, "JetBrains.Profiler.PdbServer")]
    [TestCase(VerifySignatureStatus.Valid, "cat")]
    [TestCase(VerifySignatureStatus.Valid, "env-wrapper.x64")]
    [TestCase(VerifySignatureStatus.Valid, "libMonoSupportW.x64.dylib")]
    [TestCase(VerifySignatureStatus.Valid, "libhostfxr.dylib")]
    public async Task VerifySignTest(VerifySignatureStatus expectedResult, string machoResourceName)
    {
      var verificationParams = new SignatureVerificationParams(buildChain: false, withRevocationCheck: false);
      foreach (var section in GetMachOFile(machoResourceName).Sections)
      {
        var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
        var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
        var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
        Assert.AreEqual(expectedResult, result.Status);
      }
    }

    [TestCase("libSystem.Net.Security.Native.dylib")]
    public void VerifySignInvalidSignatureFormat(string machoResourceName)
    {
      foreach (var section in GetMachOFile(machoResourceName).Sections)
      {
        Action action = () => SignedMessage.CreateInstance(section.SignatureData);
        action.Should()
          .Throw<Exception>()
          .WithMessage("Invalid signature format");
      }
    }


    [TestCase(VerifySignatureStatus.Valid, apple_root, "JetBrains.Profiler.PdbServer")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "cat")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "env-wrapper.x64")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libMonoSupportW.x64.dylib")]
    [TestCase(VerifySignatureStatus.Valid, apple_root, "libhostfxr.dylib")]
    public void VerifySignWithChainTest(
      VerifySignatureStatus expectedResult,
      string codesignRootCertStoreResourceName,
      string machOResourceName)
    {
      var results = ResourceUtil.OpenRead(ResourceCategory.MachO, codesignRootCertStoreResourceName, codeSignRootsStream =>
        {
          var verificationParams = new SignatureVerificationParams(codeSignRootsStream, withRevocationCheck: false);
          return GetMachOFile(machOResourceName).Sections
            .Select(async section =>
              {
                var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
                var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
                return await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
              })
            .Select(_ => _.Result)
            .ToList();
        });

      foreach (VerifySignatureResult result in results)
        Assert.AreEqual(expectedResult, result.Status);
    }
  }
}