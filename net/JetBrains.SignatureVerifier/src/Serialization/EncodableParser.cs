using System;
using System.Linq;
using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Serialization;

public static class EncodableParser
{
  public static IEncodableInfo ToEncodableInfo(this Asn1Object source)
  {
    if (source is Asn1TaggedObject taggedObject)
    {
      return new TaggedObjectInfo(
        taggedObject.IsExplicit(),
        taggedObject.TagNo,
        taggedObject.GetObject().ToAsn1Object().ToEncodableInfo()
      );
    }

    if (source is Asn1Sequence sequence)
    {
      return new SequenceInfo(sequence
        .ToArray()
        .Select(item => item.ToAsn1Object().ToEncodableInfo())
        .ToList()
      );
    }

    if (source is Asn1Set set)
    {
      return new SetInfo(set
        .ToArray()
        .Select(item => item.ToAsn1Object().ToEncodableInfo())
        .ToList()
      );
    }

    try
    {
      return TextualInfo.GetInstance(source);
    }
    catch (Exception e)
    {
      Console.WriteLine(e);
      throw;
    }
  }
}