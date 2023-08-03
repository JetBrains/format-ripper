using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class CertificateInfo : IEncodableInfo
{
  public X509CertificateInfo X509CertificateInfo { get; }
  public AlgorithmInfo SignatureAlgorithm { get; }
  public TextualInfo SignatureData { get; }

  public CertificateInfo(X509CertificateInfo X509CertificateInfo, AlgorithmInfo signatureAlgorithm, TextualInfo signatureData)
  {
    this.X509CertificateInfo = X509CertificateInfo;
    SignatureAlgorithm = signatureAlgorithm;
    SignatureData = signatureData;
  }

  public static IEncodableInfo GetInstance(X509CertificateStructure x509CertificateStructure)
    => new CertificateInfo(
      X509CertificateInfo.GetInstance(x509CertificateStructure.TbsCertificate),
      new AlgorithmInfo(x509CertificateStructure.SignatureAlgorithm),
      TextualInfo.GetInstance(new DerBitString(x509CertificateStructure.GetSignatureOctets()))
    );

  public static IEncodableInfo GetInstance(Asn1Object obj)
  {
    switch (obj)
    {
      case DerSequence sequence:
        return GetInstance(X509CertificateStructure.GetInstance(sequence));

      default:
        throw new ArgumentException("Unexpected object type");
    }
  }

  private DerSequence ToDLSequence()
  {
    return new DerSequence(
      X509CertificateInfo.ToPrimitive(),
      SignatureAlgorithm.ToPrimitive(),
      SignatureData.ToPrimitive());
  }

  // public X509CertificateHolder toX509CertificateHolder() => new X509CertificateHolder(
  //   Certificate.GetInstance(ToPrimitive()));

  public Asn1Encodable ToPrimitive() => ToDLSequence();

  // public static Asn1Set RecreateCertificatesFromStore(IStore<X509CertificateHolder> store)
  // {
  //   var matches = store.GetMatches(null).ToList();
  //   return new DerSet(matches.Select(c => c.ToAsn1Structure()).ToArray());
  // }
}