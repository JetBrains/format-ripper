using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class RdNInfo : IEncodableInfo
{
  [JsonProperty("Type")] private TextualInfo _type;
  [JsonProperty("Value")] private TextualInfo _value;

  [JsonConstructor]
  public RdNInfo(TextualInfo type, TextualInfo value)
  {
    _type = type;
    _value = value;
  }

  public Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo> { _type, _value }.ToPrimitiveDerSequence();
}