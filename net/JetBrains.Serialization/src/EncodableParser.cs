using System;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

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
      {
        if (TryAlgorithmInfo(sequence) is { } algorithmInfo) return algorithmInfo;
        if (TryEncapContentInfo(sequence) is { } encapContentInfo) return encapContentInfo;
        if (TryCertificateInfo(sequence) is { } certificateInfo) return certificateInfo;

        return new SequenceInfo(sequence
          .ToArray()
          .Select(item => item.ToAsn1Object().ToEncodableInfo())
          .ToList()
        );
      }

      case Asn1Set set:
        return new SetInfo(set
          .ToArray()
          .Select(item => item.ToAsn1Object().ToEncodableInfo())
          .ToList()
        );

      default:
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

  private static EncapContentInfo? TryEncapContentInfo(Asn1Sequence sequence)
  {
    try
    {
      return EncapContentInfo.GetInstance(ContentInfo.GetInstance(sequence));
    }
    catch (Exception)
    {
      return null;
    }
  }

  private static IEncodableInfo? TryCertificateInfo(Asn1Sequence sequence)
  {
    try
    {
      return CertificateInfo.GetInstance(sequence.ToAsn1Object());
    }
    catch (Exception)
    {
      return null;
    }
  }

  private static AlgorithmInfo? TryAlgorithmInfo(Asn1Sequence sequence)
  {
    try
    {
      if (SerializationUtils.AlgorithmNameFromId((DerObjectIdentifier)sequence.ToArray().First())
          == sequence.ToArray().First().ToString())
      {
        return null;
      }

      return new AlgorithmInfo(
        AlgorithmIdentifier.GetInstance(sequence)
      );
    }
    catch (Exception)
    {
      return null;
    }
  }
}