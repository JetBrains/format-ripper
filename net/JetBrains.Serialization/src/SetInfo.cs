using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class SetInfo : IEncodableInfo
{
  [JsonProperty("Content")] private readonly List<IEncodableInfo> _content;

  [JsonConstructor]
  public SetInfo(List<IEncodableInfo> content)
  {
    _content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return _content.ToPrimitiveDerSet();
  }
}