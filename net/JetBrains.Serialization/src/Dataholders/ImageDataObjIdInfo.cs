using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using System.Collections.Generic;
using System.Linq;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ImageDataObjIdInfo : IEncodableInfo
{
  [JsonProperty("Identifier")] public TextualInfo Identifier { get; }

  [JsonProperty("HexCode")] public TextualInfo HexCode { get; }

  [JsonProperty("Content")] public IEncodableInfo Content { get; }

  [JsonConstructor]
  public ImageDataObjIdInfo(TextualInfo identifier, TextualInfo hexCode, IEncodableInfo content)
  {
    Identifier = identifier;
    HexCode = hexCode;
    Content = content;
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
            .Select(it => TextualInfo.GetInstance(it))
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
      Identifier.ToPrimitive(),
      Content is SequenceInfo
        ? new List<Asn1Encodable?> { HexCode.ToPrimitive() }
          .Concat(
            ((SequenceInfo)Content)
            .PrimitiveContent()
          )
          .ToDerSequence()
        : new List<IEncodableInfo?> { HexCode, Content }.ToPrimitiveDerSequence()
    }.ToDerSequence();
}