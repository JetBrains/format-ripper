using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MSCertificateTemplateV2AttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }

  [JsonProperty("Content")] private List<List<TaggedObjectInfo>> _content;

  [JsonConstructor]
  public MSCertificateTemplateV2AttributeInfo(TextualInfo identifier, List<List<TaggedObjectInfo>> content)
  {
    Identifier = identifier;
    _content = content;
  }

  public MSCertificateTemplateV2AttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    _content = attribute.AttrValues.ToArray().OfType<Asn1Sequence>().Select(seq =>
        seq.OfType<DerTaggedObject>()
          .Select(outer => new TaggedObjectInfo(outer.IsExplicit(), outer.TagNo, new TaggedObjectInfo(
            ((DerTaggedObject)outer.GetObject()).IsExplicit(),
            ((DerTaggedObject)outer.GetObject()).TagNo,
            TextualInfo.GetInstance(((DerTaggedObject)outer.GetObject()).GetObject()))))
          .ToList())
      .ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    _content.Select(list => list.ToPrimitiveDerSequence()).ToDerSet();
}