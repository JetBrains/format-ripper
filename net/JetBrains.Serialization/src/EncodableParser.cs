using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

public static class EncodableParser
{
  public static IEncodableInfo ToEncodableInfo(this Asn1Object source)
  {
    switch (source)
    {
      case Asn1TaggedObject taggedObject:
        return new TaggedObjectInfo(
          taggedObject.IsExplicit(),
          taggedObject.TagNo,
          taggedObject.GetObject().ToAsn1Object().ToEncodableInfo()
        );

      case Asn1Sequence sequence:
        return new SequenceInfo(sequence
          .ToArray()
          .Select(item => item.ToAsn1Object().ToEncodableInfo())
          .ToList()
        );

      case Asn1Set set:
        return new SetInfo(set
          .ToArray()
          .Select(item => item.ToAsn1Object().ToEncodableInfo())
          .ToList()
        );

      default:
        return TextualInfo.GetInstance(source);
    }
  }
}