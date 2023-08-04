using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class RdNInfo : IEncodableInfo
{
  [JsonProperty("Type")] public TextualInfo Type { get; }
  [JsonProperty("Value")] public TextualInfo Value { get; }

  [JsonConstructor]
  public RdNInfo(TextualInfo type, TextualInfo value)
  {
    Type = type;
    Value = value;
  }

  public Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo> { Type, Value }.ToPrimitiveDerSequence();
}