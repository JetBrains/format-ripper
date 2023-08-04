using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System.Collections.Generic;
using System.Linq;

[JsonObject(MemberSerialization.Fields)]
public class MSCertificateTemplateV2AttributeInfo : AttributeInfo
{
    public override TextualInfo Identifier { get; }
    public List<List<TaggedObjectInfo>> Content { get; }

    public MSCertificateTemplateV2AttributeInfo(Attribute attribute)
    {
        Identifier = TextualInfo.GetInstance(attribute.AttrType);
        Content = attribute.AttrValues.ToArray().OfType<Asn1Sequence>().Select(seq =>
            seq.OfType<DerTaggedObject>()
               .Select(outer => new TaggedObjectInfo(outer.IsExplicit(), outer.TagNo, new TaggedObjectInfo(
                    ((DerTaggedObject)outer.GetObject()).IsExplicit(),
                    ((DerTaggedObject)outer.GetObject()).TagNo,
                    TextualInfo.GetInstance(((DerTaggedObject)outer.GetObject()).GetObject()))))
               .ToList())
           .ToList();
    }

    public override Asn1Encodable GetPrimitiveContent() => Content.Select(list => list.ToPrimitiveDerSequence()).ToDerSet();
}