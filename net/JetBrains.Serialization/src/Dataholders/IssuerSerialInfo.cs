using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class IssuerSerialInfo : IEncodableInfo
{
  [JsonProperty("GeneralNames")] private List<GeneralNameInfo> _generalNames;
  [JsonProperty("Serial")] private TextualInfo _serial;
  [JsonProperty("IssuerUID")] private TextualInfo? _issuerUid;

  [JsonConstructor]
  public IssuerSerialInfo(List<GeneralNameInfo> generalNames, TextualInfo serial, TextualInfo? issuerUid)
  {
    _generalNames = generalNames;
    _serial = serial;
    _issuerUid = issuerUid;
  }

  public IssuerSerialInfo(IssuerSerial issuer)
  {
    _generalNames = issuer.Issuer.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
    _serial = TextualInfo.GetInstance(issuer.Serial);
    _issuerUid = issuer.IssuerUid != null ? TextualInfo.GetInstance(issuer.IssuerUid) : null;
  }

  public Asn1Encodable ToPrimitive()
  {
    var asn1Items = new List<Asn1Encodable>
    {
      _generalNames.ToPrimitiveDerSequence(),
      _serial.ToPrimitive()
    };

    if (_issuerUid != null)
    {
      asn1Items.Add(_issuerUid.ToPrimitive());
    }

    return asn1Items.ToDerSequence();
  }
}