using Org.BouncyCastle.Asn1;

namespace JetBrains.SignatureVerifier.Serialization;

public class TaggedObjectInfo : IEncodableInfo
{
  private readonly bool _explicit;
  private readonly int _tagNo;
  private readonly IEncodableInfo _content;
  
  public TaggedObjectInfo(bool explicitness, int tagNo, IEncodableInfo content)
  {
    _explicit = explicitness;
    _tagNo = tagNo;
    _content = content;
  }

  public static DerTaggedObject GetTaggedObject(bool explicitness, int tagNo, Asn1Encodable content)
  {
    return new DerTaggedObject(explicitness, tagNo, content);
  }

  public Asn1Encodable ToPrimitive()
  {
    return GetTaggedObject(_explicit, _tagNo, _content.ToPrimitive()).ToAsn1Object();
  }
}