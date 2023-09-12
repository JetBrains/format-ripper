using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class V2CertificateAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }

  [JsonProperty("Content")] private IEncodableInfo _content;

  [JsonConstructor]
  public V2CertificateAttributeInfo(TextualInfo identifier, IEncodableInfo content)
  {
    Identifier = identifier;
    _content = content;
  }

  public V2CertificateAttributeInfo(Attribute attribute)
    : this(TextualInfo.GetInstance(attribute.AttrType), attribute.AttrValues.ToEncodableInfo())
  {
  }

  public override Asn1Encodable GetPrimitiveContent() => _content.ToPrimitive();
}