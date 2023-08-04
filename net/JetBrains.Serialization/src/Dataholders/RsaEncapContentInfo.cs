using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class RsaEncapContentInfo : EncapContentInfo
{
  [JsonProperty("ContentType")] protected override TextualInfo ContentType { get; }
  [JsonProperty("Content")] public TextualInfo? Content { get; }

  [JsonConstructor]
  public RsaEncapContentInfo(TextualInfo contentType, TextualInfo? content)
  {
    ContentType = contentType;
    Content = content;
  }

  public RsaEncapContentInfo(ContentInfo contentInfo)
    : this(TextualInfo.GetInstance(contentInfo.ContentType),
      contentInfo.Content != null ? TextualInfo.GetInstance(contentInfo.Content) : null)
  {
  }

  protected override Asn1Encodable? GetContentPrimitive() => Content?.ToPrimitive();
}