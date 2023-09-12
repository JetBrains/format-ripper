using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class TSTInfo : IEncodableInfo
{
  [JsonProperty("Identifier")] private TextualInfo _identifier;
  [JsonProperty("Content")] private TaggedObjectInfo _content;

  [JsonConstructor]
  public TSTInfo(TextualInfo identifier, TaggedObjectInfo content)
  {
    _identifier = identifier;
    _content = content;
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
      _identifier,
      _content
    }.ToPrimitiveDerSequence();
}