using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;
[JsonObject(MemberSerialization.Fields)]
public class UnknownEncapContentInfo : EncapContentInfo
{
  protected override TextualInfo ContentType { get; }
  private IEncodableInfo? Content { get; }

  public UnknownEncapContentInfo(TextualInfo contentType, IEncodableInfo? content)
  {
    ContentType = contentType;
    Content = content;
  }

  public UnknownEncapContentInfo(ContentInfo contentInfo)
    : this(TextualInfo.GetInstance(contentInfo.ContentType),
      contentInfo.Content?.ToAsn1Object()?.ToEncodableInfo())
  {
  }

  protected override Asn1Encodable? GetContentPrimitive() => Content?.ToPrimitive();
}