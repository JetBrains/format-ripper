using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MSCertExtensionsAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }

  [JsonProperty("Content")] private List<List<TextualInfo>> _content;

  [JsonConstructor]
  public MSCertExtensionsAttributeInfo(TextualInfo identifier, List<List<TextualInfo>> content)
  {
    Identifier = identifier;
    _content = content;
  }

  public MSCertExtensionsAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    _content = attribute.AttrValues.ToArray().OfType<Asn1Sequence>().Select(seq =>
      seq.OfType<Asn1Encodable>().Select(TextualInfo.GetInstance).ToList()).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    _content.Select(list => list.ToPrimitiveDerSequence()).ToDerSet();
}