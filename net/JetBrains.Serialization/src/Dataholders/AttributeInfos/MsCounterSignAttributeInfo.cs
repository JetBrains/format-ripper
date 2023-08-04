using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class MsCounterSignAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("ContentIdentifier")] public List<TextualInfo> ContentIdentifier { get; }

  [JsonProperty("Content")] public List<TaggedObjectInfo> Content { get; }

  [JsonConstructor]
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
      .ToPrimitiveList()
      .Zip(
        Content.ToPrimitiveList(),
        (first, second) => new List<Asn1Encodable?> { first, second }.ToDerSequence())
      .ToDerSet();
}