using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ContentTypeAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public List<TextualInfo> Content { get; }

  [JsonConstructor]
  public ContentTypeAttributeInfo(TextualInfo identifier, List<TextualInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public ContentTypeAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => TextualInfo.GetInstance(item)).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}