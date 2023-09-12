using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class CertificateInfo : IEncodableInfo
{
  [JsonProperty("XCertificateInfo")] private XCertificateInfo _xCertificateInfo;

  [JsonProperty("SignatureAlgorithm")] private AlgorithmInfo _signatureAlgorithm;

  [JsonProperty("SignatureData")] private TextualInfo _signatureData;

  [JsonConstructor]
  private CertificateInfo(XCertificateInfo xCertificateInfo, AlgorithmInfo signatureAlgorithm,
    TextualInfo signatureData)
  {
    _xCertificateInfo = xCertificateInfo;
    _signatureAlgorithm = signatureAlgorithm;
    _signatureData = signatureData;
  }

  public static CertificateInfo GetInstance(X509CertificateStructure x509CertificateStructure)
    => new CertificateInfo(
      XCertificateInfo.GetInstance(x509CertificateStructure.TbsCertificate),
      new AlgorithmInfo(x509CertificateStructure.SignatureAlgorithm),
      TextualInfo.GetInstance(new DerBitString(x509CertificateStructure.GetSignatureOctets()))
    );

  public static CertificateInfo GetInstance(AttributeCertificate attributeCertificate)
    => new CertificateInfo(
      XCertificateInfo.GetInstance(attributeCertificate),
      new AlgorithmInfo(attributeCertificate.SignatureAlgorithm),
      TextualInfo.GetInstance(new DerBitString(attributeCertificate.GetSignatureOctets()))
    );

  public static IEncodableInfo GetInstance(Asn1Object obj)
  {
    switch (obj)
    {
      case DerSequence sequence:
        return GetInstance(X509CertificateStructure.GetInstance(sequence));

      case Asn1TaggedObject taggedObject:
        return new TaggedObjectInfo(
          taggedObject.IsExplicit(),
          taggedObject.TagNo,
          GetInstance(AttributeCertificate.GetInstance(taggedObject.GetObject()))
        );

      default:
        throw new ArgumentException("Unexpected object type");
    }
  }

  private DerSequence ToDLSequence() =>
    new List<IEncodableInfo?>
    {
      _xCertificateInfo,
      _signatureAlgorithm,
      _signatureData
    }.ToPrimitiveDerSequence();

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}