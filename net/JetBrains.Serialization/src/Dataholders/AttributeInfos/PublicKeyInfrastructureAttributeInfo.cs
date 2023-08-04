using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class PublicKeyInfrastructureAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public IEncodableInfo Content { get; }

  public PublicKeyInfrastructureAttributeInfo(TextualInfo identifier, IEncodableInfo content)
  {
    Identifier = identifier;
    Content = content;
  }

  public PublicKeyInfrastructureAttributeInfo(Attribute attribute)
    : this(TextualInfo.GetInstance(attribute.AttrType), attribute.AttrValues.ToEncodableInfo())
  {
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitive();
}