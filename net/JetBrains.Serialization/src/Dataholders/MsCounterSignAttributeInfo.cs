using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class MsCounterSignAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<TextualInfo> ContentIdentifier { get; }
  public List<TaggedObjectInfo> Content { get; }

  public MsCounterSignAttributeInfo(TextualInfo identifier, List<TextualInfo> contentIdentifier,
    List<TaggedObjectInfo> content)
  {
    Identifier = identifier;
    ContentIdentifier = contentIdentifier;
    Content = content;
  }

  public MsCounterSignAttributeInfo(Attribute attribute)
    : this(
      TextualInfo.GetInstance(attribute.AttrType),
      attribute.AttrValues.ToArray().Select(av => TextualInfo.GetInstance(((Asn1Sequence)av)[0])).ToList(),
      attribute.AttrValues.ToArray().Select(av =>
      {
        var sequence = (Asn1Sequence)av;
        var lastElement = sequence[1];
        return new TaggedObjectInfo(
          ((DerTaggedObject)lastElement).IsExplicit(),
          ((DerTaggedObject)lastElement).TagNo,
          MsCounterSignatureInfo.GetInstance((DerSequence)((DerTaggedObject)lastElement).GetObject())
        );
      }).ToList()
    )
  {
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    ContentIdentifier
      .Cast<IEncodableInfo>()
      .ToList()
      .ToPrimitiveList().Zip(
        Content.Cast<IEncodableInfo>().ToList().ToPrimitiveList(),
        (first, second) => new List<Asn1Encodable?> { first, second }.ToDerSequence())
      .Cast<Asn1Encodable>()
      .ToList()
      .ToDerSet();
}