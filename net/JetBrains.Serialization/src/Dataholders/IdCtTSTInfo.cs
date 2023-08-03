using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class IdCtTSTInfo : EncapContentInfo
{
  protected override TextualInfo ContentType { get; }
  public TextualInfo Content { get; }

  public IdCtTSTInfo(TextualInfo contentType, TextualInfo content)
  {
    ContentType = contentType;
    Content = content;
  }

  public IdCtTSTInfo(ContentInfo contentInfo)
    : this(TextualInfo.GetInstance(contentInfo.ContentType), TextualInfo.GetInstance(contentInfo.Content))
  {
  }

  protected override Asn1Encodable GetContentPrimitive() => Content.ToPrimitive();
}