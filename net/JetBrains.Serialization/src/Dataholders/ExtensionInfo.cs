using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ExtensionInfo : IEncodableInfo
{
  [JsonProperty("Key")] private TextualInfo _key;
  [JsonProperty("Critical")] private bool _critical;
  [JsonProperty("Value")] private TextualInfo _value;

  [JsonConstructor]
  public ExtensionInfo(TextualInfo key, bool critical, TextualInfo value)
  {
    _key = key;
    _critical = critical;
    _value = value;
  }

  private DerSequence ToDLSequence() =>
    new List<Asn1Encodable?>
      { _key.ToPrimitive(), _critical ? DerBoolean.True : null, _value.ToPrimitive() }.ToDerSequence();

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}