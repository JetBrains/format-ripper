using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class UnknownEncapContentInfo : EncapContentInfo
{
  [JsonProperty("ContentType")] protected override TextualInfo ContentType { get; }
  [JsonProperty("Content")] private IEncodableInfo? Content { get; }

  [JsonConstructor]
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