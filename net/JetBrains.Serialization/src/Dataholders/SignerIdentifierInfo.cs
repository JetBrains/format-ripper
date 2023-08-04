using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class SignerIdentifierInfo : IEncodableInfo
{
  [JsonProperty("IssuerInfo")] public X509NameInfo IssuerInfo { get; }
  [JsonProperty("SerialNumber")] public TextualInfo SerialNumber { get; }

  [JsonConstructor]
  public SignerIdentifierInfo(X509NameInfo issuerInfo, TextualInfo serialNumber)
  {
    IssuerInfo = issuerInfo;
    SerialNumber = serialNumber;
  }

  public SignerIdentifierInfo(
    X509Name issuerName,
    DerInteger serialNumber)
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