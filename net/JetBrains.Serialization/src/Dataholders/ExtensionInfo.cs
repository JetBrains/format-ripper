using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class ExtensionInfo : IEncodableInfo
{
  public TextualInfo Key { get; }
  public bool Critical { get; }
  public TextualInfo Value { get; }

  public ExtensionInfo(TextualInfo key, bool critical, TextualInfo value)
  {
    Key = key;
    Critical = critical;
    Value = value;
  }

  private DerSequence ToDLSequence() =>
    new DerSequence(
      new[] {Key.ToPrimitive(), Critical ? DerBoolean.True : null, Value.ToPrimitive()}
        .OfType<Asn1Encodable>()
        .ToArray());

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}