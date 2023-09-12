using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

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
        if (TryX509NameInfo(sequence) is { } nameInfo) return nameInfo;
        if (TryAlgorithmInfo(sequence) is { } algorithmInfo) return algorithmInfo;
        // if (TryEncapContentInfo(sequence) is { } encapContentInfo) return encapContentInfo;
        // if (TryCertificateInfo(sequence) is { } certificateInfo) return certificateInfo;
        // if (TryAttributeInfo(sequence) is { } attributeInfo) return attributeInfo;

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

  private static AttributeInfo? TryAttributeInfo(Asn1Sequence sequence)
  {
    try
    {
      return AttributeInfo.GetInstance(Attribute.GetInstance(sequence));
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

  private static IEncodableInfo? TryX509NameInfo(Asn1Sequence sequence)
  {
    try
    {
      return new X509NameInfo(X509Name.GetInstance(sequence));
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