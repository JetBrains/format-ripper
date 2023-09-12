using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class RsaEncapContentInfo : EncapContentInfo
{
  [JsonProperty("ContentType")] protected override TextualInfo ContentType { get; }
  [JsonProperty("Content")] private TextualInfo? _content;

  [JsonConstructor]
  public RsaEncapContentInfo(TextualInfo contentType, TextualInfo? content)
  {
    ContentType = contentType;
    _content = content;
  }

  public RsaEncapContentInfo(ContentInfo contentInfo)
    : this(TextualInfo.GetInstance(contentInfo.ContentType),
      contentInfo.Content != null ? TextualInfo.GetInstance(contentInfo.Content) : null)
  {
  }

  protected override Asn1Encodable? GetContentPrimitive() => _content?.ToPrimitive();
}