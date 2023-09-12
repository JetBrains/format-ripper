using System;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class TaggedObjectInfo : IEncodableInfo
{
  [JsonProperty("Explicit")] private bool _explicit;
  [JsonProperty("TagNo")] private int _tagNo;
  [JsonProperty("Content")] private IEncodableInfo _content;

  [JsonConstructor]
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