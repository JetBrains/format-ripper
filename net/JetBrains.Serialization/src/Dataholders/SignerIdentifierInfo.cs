using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class SignerIdentifierInfo : IEncodableInfo
{
  [JsonProperty("IssuerInfo")] private X509NameInfo _issuerInfo;
  [JsonProperty("SerialNumber")] private TextualInfo _serialNumber;

  [JsonConstructor]
  public SignerIdentifierInfo(X509NameInfo issuerInfo, TextualInfo serialNumber)
  {
    _issuerInfo = issuerInfo;
    _serialNumber = serialNumber;
  }

  public SignerIdentifierInfo(
    X509Name issuerName,
    DerInteger serialNumber)
  {
    _issuerInfo = new X509NameInfo(issuerName);
    _serialNumber = TextualInfo.GetInstance(serialNumber);
  }

  public Asn1Encodable ToPrimitive() => new List<IEncodableInfo?>
  {
    _issuerInfo,
    _serialNumber
  }.ToPrimitiveDerSequence();
}