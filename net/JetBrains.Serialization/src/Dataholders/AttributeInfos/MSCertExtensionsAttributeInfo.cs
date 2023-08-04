using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MSCertExtensionsAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public List<List<TextualInfo>> Content { get; }

  [JsonConstructor]
  public MSCertExtensionsAttributeInfo(TextualInfo identifier, List<List<TextualInfo>> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public MSCertExtensionsAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().OfType<Asn1Sequence>().Select(seq =>
      seq.OfType<Asn1Encodable>().Select(val => TextualInfo.GetInstance(val)).ToList()).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    Content.Select(list => list.ToPrimitiveDerSequence()).ToDerSet();
}