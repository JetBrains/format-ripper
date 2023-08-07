using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.SignatureVerifier.Crypt.BC;
using Newtonsoft.Json;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;

namespace JetBrains.Serialization.Tests;

public class SignatureRecreationTests
{
  // @formatter:off
  [TestCase("ServiceModelRegUI.dll")]
  [TestCase("shell32.dll")]
  [TestCase("IntelAudioService.exe")]
  [TestCase("libcrypto-1_1-x64.dll")]
  [TestCase("libssl-1_1-x64.dll")]
  [TestCase("JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe")]
  // @formatter:on
  public async Task PeRecreationTest(string resourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Pe, resourceName,
      stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

    var verificationParams = new SignatureVerificationParams(null, null, false, false);
    var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
    var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
    var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

    RecreationTest(signedMessage.SignedData, file.SignatureData.CmsBlob!);
  }

  // @formatter:off
  [TestCase("2dac4b.msi")]
  [TestCase("firefox.msi")]
  [TestCase("sumatra.msi")]
  // @formatter:on
  public async Task MsiRecreationTest(string resourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Msi, resourceName, stream =>
    {
      Assert.IsTrue(CompoundFile.Is(stream));
      return CompoundFile.Parse(stream, CompoundFile.Mode.SignatureData);
    });

    var verificationParams = new SignatureVerificationParams(null, null, false, false);
    var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
    var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
    var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

    RecreationTest(signedMessage.SignedData, file.SignatureData.CmsBlob!);
  }

  private static MachOFile GetMachOFile(string resourceName) =>
    ResourceUtil.OpenRead(ResourceCategory.MachO, resourceName,
      stream => MachOFile.Parse(stream, MachOFile.Mode.SignatureData));

  // @formatter:off
  [TestCase("JetBrains.Profiler.PdbServer")]
  [TestCase("cat")]
  [TestCase("env-wrapper.x64")]
  [TestCase("libMonoSupportW.x64.dylib")]
  [TestCase("libhostfxr.dylib")]
  // @formatter:on
  public async Task MachORecreationTest(string resourceName)
  {
    var verificationParams = new SignatureVerificationParams(buildChain: false, withRevocationCheck: false);
    foreach (var section in GetMachOFile(resourceName).Sections)
    {
      var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
      var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
      var result = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      RecreationTest(signedMessage.SignedData, section.SignatureData.CmsBlob!, "BER");
    }
  }

  public ContentInfo SignedDataToContentInfo(SignedData signedData, string encoding = "BER")
  {
    byte[] signedDataBytes = signedData.GetEncoded(encoding);

    Asn1InputStream inputStream = new Asn1InputStream(signedDataBytes);
    Asn1Object asn1Object = inputStream.ReadObject();

    return new ContentInfo(PkcsObjectIdentifiers.SignedData, asn1Object);
  }

  public void RecreationTest(CmsSignedData signedData, byte[] originalSignature, string encoding = "DER")
  {
    var innerSignedData = signedData.SignedData;
    var signedDataInfo = new SignedDataInfo(signedData); //innerSignedData.ToAsn1Object().ToEncodableInfo();

    var settings = new JsonSerializerSettings
    {
      TypeNameHandling = TypeNameHandling.Auto
    };
    var json = JsonConvert.SerializeObject(signedDataInfo, settings);
    var recreated = JsonConvert.DeserializeObject<SignedDataInfo>(json, settings);

    var copy = SignedData.GetInstance(recreated.ToPrimitive());
    Assert.That(innerSignedData.GetEncoded("DER").SequenceEqual(copy.GetEncoded("DER")));

    var recreatedInfo = SignedDataToContentInfo(copy);
    Assert.That(signedData.ContentInfo.GetEncoded(encoding).SequenceEqual(recreatedInfo.GetEncoded(encoding)));

    var cropped = new ArraySegment<byte>(originalSignature, 0, recreatedInfo.GetEncoded(encoding).Length);
    Assert.That(cropped.ToArray().SequenceEqual(recreatedInfo.GetEncoded(encoding)));
  }
}