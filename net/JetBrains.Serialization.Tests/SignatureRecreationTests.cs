using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using JetBrains.SignatureVerifier.Serialization;
using Newtonsoft.Json;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization.Tests;

public class SignatureRecreationTests
{
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
  public Task PeVerifySignTest(VerifySignatureStatus expectedResult, string peResourceName)
  {
    var file = ResourceUtil.OpenRead(ResourceCategory.Pe, peResourceName,
      stream => PeFile.Parse(stream, PeFile.Mode.SignatureData));

    var signedMessage = SignedMessage.CreateInstance(file.SignatureData);
    var originalContentInfo = signedMessage.SignedData.ContentInfo;
    VerifySignTest(originalContentInfo);

    return Task.CompletedTask;
  }

  public void VerifySignTest(ContentInfo originalContentInfo, string encoding = "DER")
  {
    var encodable = originalContentInfo.ToAsn1Object().ToEncodableInfo();
    var settings = new JsonSerializerSettings
    {
      TypeNameHandling = TypeNameHandling.Auto
    };
    var json = JsonConvert.SerializeObject(encodable, settings);
    var recreated = JsonConvert.DeserializeObject<SequenceInfo>(json, settings);

    Assert.That(originalContentInfo.GetEncoded(encoding).SequenceEqual(recreated.ToPrimitive().GetEncoded(encoding)));
  }
}