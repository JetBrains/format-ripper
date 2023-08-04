using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

[JsonObject(MemberSerialization.OptIn)]
public class IssuerSerialInfo : IEncodableInfo
{
  [JsonProperty("GeneralNames")] public List<GeneralNameInfo> GeneralNames { get; set; }
  [JsonProperty("Serial")] public TextualInfo Serial { get; set; }
  [JsonProperty("IssuerUID")] public TextualInfo? IssuerUID { get; set; }

  [JsonConstructor]
  public IssuerSerialInfo(List<GeneralNameInfo> generalNames, TextualInfo serial)
  {
    GeneralNames = generalNames;
    Serial = serial;
  }

  public IssuerSerialInfo(IssuerSerial issuer)
  {
    GeneralNames = issuer.Issuer.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
    Serial = TextualInfo.GetInstance(issuer.Serial);
    IssuerUID = issuer.IssuerUid != null ? TextualInfo.GetInstance(issuer.IssuerUid) : null;
  }

  public Asn1Encodable ToPrimitive()
  {
    var asn1Items = new List<Asn1Encodable>
    {
      GeneralNames.ToPrimitiveDerSequence(),
      Serial.ToPrimitive()
    };

    if (IssuerUID != null)
    {
      asn1Items.Add(IssuerUID.ToPrimitive());
    }

    return asn1Items.ToDerSequence();
  }
}