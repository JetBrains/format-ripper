using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using System.Collections.Generic;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ExtensionInfo : IEncodableInfo
{
  [JsonProperty("Key")] public TextualInfo Key { get; }

  [JsonProperty("Critical")] public bool Critical { get; }

  [JsonProperty("Value")] public TextualInfo Value { get; }

  [JsonConstructor]
  public ExtensionInfo(TextualInfo key, bool critical, TextualInfo value)
  {
    Key = key;
    Critical = critical;
    Value = value;
  }

  private DerSequence ToDLSequence() =>
    new List<Asn1Encodable>
      { Key.ToPrimitive(), Critical ? DerBoolean.True : null, Value.ToPrimitive() }.ToDerSequence();

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}