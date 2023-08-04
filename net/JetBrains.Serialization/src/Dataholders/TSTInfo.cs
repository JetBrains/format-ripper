using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class TSTInfo : IEncodableInfo
{
  public TextualInfo Identifier { get; }
  public TaggedObjectInfo Content { get; }

  public TSTInfo(TextualInfo identifier, TaggedObjectInfo content)
  {
    Identifier = identifier;
    Content = content;
  }

  public TSTInfo(DerSequence sequence)
    : this(
      TextualInfo.GetInstance(sequence[0]),
      new TaggedObjectInfo(
        ((DerTaggedObject)sequence[1]).IsExplicit(),
        ((DerTaggedObject)sequence[1]).TagNo,
        TextualInfo.GetInstance(((DerTaggedObject)sequence[1]).GetObject())))
  {
  }

  public virtual Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo?>
    {
      Identifier,
      Content
    }.ToPrimitiveDerSequence();
}