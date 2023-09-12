using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ImageDataObjIdInfo : IEncodableInfo
{
  [JsonProperty("Identifier")] private TextualInfo _identifier;
  [JsonProperty("HexCode")] private TextualInfo _hexCode;
  [JsonProperty("Content")] private IEncodableInfo _content;

  [JsonConstructor]
  public ImageDataObjIdInfo(TextualInfo identifier, TextualInfo hexCode, IEncodableInfo content)
  {
    _identifier = identifier;
    _hexCode = hexCode;
    _content = content;
  }

  public static ImageDataObjIdInfo GetInstance(DerSequence sequence)
  {
    var id = TextualInfo.GetInstance(sequence.ToArray().First());
    var seq = (DerSequence)sequence.ToArray().Last();

    var iterator = seq.GetEnumerator();

    iterator.MoveNext();
    var hexCode = TextualInfo.GetInstance((Asn1Encodable)iterator.Current!);

    IEncodableInfo content;
    iterator.MoveNext();
    var next = (Asn1Encodable)iterator.Current!;

    if (next is DerTaggedObject)
    {
      var taggedObject = (DerTaggedObject)seq.ToArray().Last();
      var secondLevelTaggedObject = (DerTaggedObject)taggedObject.GetObject();
      IEncodableInfo thirdLevelObject = secondLevelTaggedObject.GetObject() switch
      {
        DerTaggedObject obj => new TaggedObjectInfo(
          obj.IsExplicit(),
          obj.TagNo,
          TextualInfo.GetInstance(obj.GetObject())),

        DerSequence seqObj => new SequenceInfo(
          seqObj
            .Cast<Asn1Encodable>()
            .Select(TextualInfo.GetInstance)
            .Cast<IEncodableInfo>()
            .ToList()
        ),

        _ => throw new ArgumentException($"Unexpected object type {secondLevelTaggedObject.GetObject().GetType().Name}")
      };


      content = new TaggedObjectInfo(
        taggedObject.IsExplicit(),
        taggedObject.TagNo,
        new TaggedObjectInfo(
          secondLevelTaggedObject.IsExplicit(),
          secondLevelTaggedObject.TagNo,
          thirdLevelObject));
    }
    else
    {
      var list = new List<TextualInfo> { TextualInfo.GetInstance(next) };
      while (iterator.MoveNext())
        list.Add(TextualInfo.GetInstance((Asn1Encodable)iterator.Current!));

      content = new SequenceInfo(list.Cast<IEncodableInfo>().ToList());
    }

    return new ImageDataObjIdInfo(id, hexCode, content);
  }

  public Asn1Encodable ToPrimitive()
    => new List<Asn1Encodable?>
    {
      _identifier.ToPrimitive(),
      _content is SequenceInfo sequenceInfo
        ? new List<Asn1Encodable?> { _hexCode.ToPrimitive() }
          .Concat(
            sequenceInfo
              .PrimitiveContent()
          )
          .ToDerSequence()
        : new List<IEncodableInfo?> { _hexCode, _content }.ToPrimitiveDerSequence()
    }.ToDerSequence();
}