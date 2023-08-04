using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class CertificateInfo : IEncodableInfo
{
  public XCertificateInfo XCertificateInfo { get; }
  public AlgorithmInfo SignatureAlgorithm { get; }
  public TextualInfo SignatureData { get; }

  private CertificateInfo(XCertificateInfo xCertificateInfo, AlgorithmInfo signatureAlgorithm,
    TextualInfo signatureData)
  {
    this.XCertificateInfo = xCertificateInfo;
    SignatureAlgorithm = signatureAlgorithm;
    SignatureData = signatureData;
  }

  public static IEncodableInfo GetInstance(X509CertificateStructure x509CertificateStructure)
    => new CertificateInfo(
      XCertificateInfo.GetInstance(x509CertificateStructure.TbsCertificate),
      new AlgorithmInfo(x509CertificateStructure.SignatureAlgorithm),
      TextualInfo.GetInstance(new DerBitString(x509CertificateStructure.GetSignatureOctets()))
    );

  public static IEncodableInfo GetInstance(AttributeCertificate attributeCertificate)
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
      XCertificateInfo,
      SignatureAlgorithm,
      SignatureData
    }.ToPrimitiveDerSequence();


  // public X509CertificateHolder toX509CertificateHolder() => new X509CertificateHolder(
  //   Certificate.GetInstance(ToPrimitive()));

  public Asn1Encodable ToPrimitive() => ToDLSequence();

  // public static Asn1Set RecreateCertificatesFromStore(IStore<X509CertificateHolder> store)
  // {
  //   var matches = store.GetMatches(null).ToList();
  //   return new DerSet(matches.Select(c => c.ToAsn1Structure()).ToArray());
  // }
}