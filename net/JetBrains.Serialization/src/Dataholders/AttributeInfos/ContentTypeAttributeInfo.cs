using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class ContentTypeAttributeInfo : AttributeInfo
{
    public override TextualInfo Identifier { get; }
    public List<TextualInfo> Content { get; }

    public ContentTypeAttributeInfo(Attribute attribute)
    {
        Identifier = TextualInfo.GetInstance(attribute.AttrType);
        Content = attribute.AttrValues.ToArray().Select(item => TextualInfo.GetInstance(item)).ToList();
    }

    public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}