using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public abstract class XCertificateInfo : IEncodableInfo
{
  public static XCertificateInfo GetInstance(Asn1Encodable obj)
  {
    switch (obj)
    {
      case TbsCertificateStructure tbs:
        return X509CertificateInfo.GetInstance(tbs);
      case AttributeCertificate attributeCertificate:
        return X509AttributeCertificateInfo.GetInstance(attributeCertificate);
      default:
        throw new ArgumentException(@"Unexpected certificate type", nameof(obj));
    }
  }

  public abstract Asn1Encodable ToPrimitive();
}