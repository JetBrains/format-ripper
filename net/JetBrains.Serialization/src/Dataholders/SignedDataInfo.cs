using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using JetBrains.Serialization;
using Org.BouncyCastle.X509;
using CmsSignedData = JetBrains.SignatureVerifier.Crypt.BC.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;

[JsonObject(MemberSerialization.OptIn)]
public class SignedDataInfo : IEncodableInfo
{
  [JsonProperty("Version")] private TextualInfo _version;
  [JsonProperty("DigestAlgorithmsInfo")] private List<AlgorithmInfo> _digestAlgorithmsInfo;
  [JsonProperty("EncapContentInfo")] private EncapContentInfo _encapContentInfo;
  [JsonProperty("Certificates")] private List<CertificateInfo> _certificates;
  [JsonProperty("CRLs")] private List<IEncodableInfo?>? _crLs;
  [JsonProperty("SignerInfos")] private List<SignerInfo> _signerInfos;

  [JsonConstructor]
  public SignedDataInfo(TextualInfo version, List<AlgorithmInfo> digestAlgorithmsInfo,
    EncapContentInfo encapContentInfo, List<CertificateInfo> certificates, List<SignerInfo> signerInfos,
    List<IEncodableInfo?>? crLs)
  {
    _version = version;
    _digestAlgorithmsInfo = digestAlgorithmsInfo;
    _encapContentInfo = encapContentInfo;
    _certificates = certificates;
    _signerInfos = signerInfos;
    _crLs = crLs;
  }

  public SignedDataInfo(CmsSignedData signedData)
  {
    _version = TextualInfo.GetInstance(signedData.SignedData.Version);
    _digestAlgorithmsInfo = signedData.DigestAlgorithmIdentifiers().Select(id => new AlgorithmInfo(id)).ToList();
    _encapContentInfo = EncapContentInfo.GetInstance(signedData.SignedData.EncapContentInfo);
    _certificates = signedData.GetCertificates("Collection").GetMatches(null)
      .OfType<X509Certificate>().Select(holder => CertificateInfo.GetInstance(holder.CertificateStructure)).ToList();
    _crLs = signedData.SignedData.CRLs?.OfType<Asn1Encodable>().Select(crl => crl?.ToAsn1Object().ToEncodableInfo())
      .ToList();
    _signerInfos = signedData.GetSignerInfos().GetSigners().OfType<SignerInformation>()
      .Select(info => new SignerInfo(info))
      .ToList();
  }

  public Asn1Encodable ToPrimitive()
  {
    return new List<Asn1Encodable?>
    {
      _version.ToPrimitive(),
      _digestAlgorithmsInfo.ToPrimitiveDerSet(),
      _encapContentInfo.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(false, 0, _certificates.ToPrimitiveDerSet()),
      _crLs?.ToPrimitiveDerSequence(),
      _signerInfos.ToPrimitiveDerSet()
    }.ToDerSequence();
  }

  public byte[] ToSignature(string encoding = "DER")
  {
    var signedData = SignedData.GetInstance(ToPrimitive());
    return signedData.ToContentInfo().GetEncoded(encoding);
  }
}