using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class CMSAlgorithmProtectionAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public IEncodableInfo Content { get; }

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