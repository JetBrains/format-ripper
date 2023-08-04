using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class SignerIdentifierInfo : IEncodableInfo
{
  public X509NameInfo IssuerInfo { get; }
  public TextualInfo SerialNumber { get; }

  public SignerIdentifierInfo(
    X509Name issuerName,
    DerInteger serialNumber
  )
  {
    IssuerInfo = new X509NameInfo(issuerName);
    SerialNumber = TextualInfo.GetInstance(serialNumber);
  }

  public Asn1Encodable ToPrimitive() => new List<IEncodableInfo?>
  {
    IssuerInfo,
    SerialNumber
  }.ToPrimitiveDerSequence();
}