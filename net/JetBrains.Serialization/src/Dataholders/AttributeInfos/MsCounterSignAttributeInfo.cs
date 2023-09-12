using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MsCounterSignAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }

  [JsonProperty("ContentIdentifier")] private List<TextualInfo> _contentIdentifier;

  [JsonProperty("Content")] private List<TaggedObjectInfo> _content;

  [JsonConstructor]
  public MsCounterSignAttributeInfo(TextualInfo identifier, List<TextualInfo> contentIdentifier,
    List<TaggedObjectInfo> content)
  {
    Identifier = identifier;
    _contentIdentifier = contentIdentifier;
    _content = content;
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
    _contentIdentifier
      .ToPrimitiveList()
      .Zip(
        _content.ToPrimitiveList(),
        (first, second) => new List<Asn1Encodable?> { first, second }.ToDerSequence())
      .ToDerSet();
}