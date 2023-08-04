using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class RdNInfo : IEncodableInfo
{
  public TextualInfo Type { get; }
  public TextualInfo Value { get; }

  public RdNInfo(TextualInfo type, TextualInfo value)
  {
    Type = type;
    Value = value;
  }

  public Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo> { Type, Value }.ToPrimitiveDerSequence();
}