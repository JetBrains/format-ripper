using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public abstract class EncapContentInfo : IEncodableInfo
{
  [JsonProperty("isBer")] private Boolean _isBer;

  protected abstract Asn1Encodable? GetContentPrimitive();

  [JsonProperty("ContentType")] protected abstract TextualInfo ContentType { get; }

  public static EncapContentInfo GetInstance(ContentInfo contentInfo)
  {
    switch (contentInfo.ContentType.Id)
    {
      case "1.3.6.1.4.1.311.2.1.4":
        return PeEncapContentInfo.GetInstance(contentInfo);
      case "1.2.840.113549.1.7.2":
        return new RsaEncapContentInfo(contentInfo);
      case "1.2.840.113549.1.9.16.1.4":
        return new IdCtTSTInfo(contentInfo);
      default:
        return new UnknownEncapContentInfo(contentInfo);
    }
  }

  public Asn1Encodable ToPrimitive()
  {
    var content = GetContentPrimitive();
    DerTaggedObject? tagged = content != null
      ? TaggedObjectInfo.GetTaggedObject(
        true,
        0,
        content
      )
      : null;

    return new List<Asn1Encodable?>
    {
      ContentType.ToPrimitive(),
      tagged
    }.ToDerSequence();
  }
}