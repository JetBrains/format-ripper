using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class SequenceInfo : IEncodableInfo
{
  [JsonProperty("Content")] private List<IEncodableInfo> _content;

  [JsonConstructor]
  public SequenceInfo(List<IEncodableInfo> content)
  {
    _content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return _content.ToPrimitiveDerSequence();
  }
}