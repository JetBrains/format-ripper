using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class V2CertificateAttributeInfo : AttributeInfo
{
    public override TextualInfo Identifier { get; }
    public IEncodableInfo Content { get; }

    public V2CertificateAttributeInfo(TextualInfo identifier, IEncodableInfo content)
    {
        Identifier = identifier;
        Content = content;
    }

    public V2CertificateAttributeInfo(Attribute attribute)
        : this(TextualInfo.GetInstance(attribute.AttrType), attribute.AttrValues.ToEncodableInfo())
    {
    }

    public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitive();
}