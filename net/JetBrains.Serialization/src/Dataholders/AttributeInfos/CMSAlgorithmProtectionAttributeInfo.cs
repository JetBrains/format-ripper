using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class CMSAlgorithmProtectionAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public IEncodableInfo Content { get; }

  [JsonConstructor]
  public CMSAlgorithmProtectionAttributeInfo(TextualInfo identifier, IEncodableInfo content)
  {
    Identifier = identifier;
    Content = content;
  }

  public CMSAlgorithmProtectionAttributeInfo(Attribute attribute)
    : this(TextualInfo.GetInstance(attribute.AttrType), attribute.AttrValues.ToEncodableInfo())
  {
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitive();
}