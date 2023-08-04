using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class CounterSignatureAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public List<CounterSignatureInfo> Content { get; }

  [JsonConstructor]
  public CounterSignatureAttributeInfo(TextualInfo identifier, List<CounterSignatureInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public CounterSignatureAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => CounterSignatureInfo.GetInstance(item as DerSequence))
      .ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}