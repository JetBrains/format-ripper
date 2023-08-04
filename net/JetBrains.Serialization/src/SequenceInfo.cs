using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class SequenceInfo : IEncodableInfo
{
  [JsonProperty("Content")] public readonly List<IEncodableInfo> Content;

  [JsonConstructor]
  public SequenceInfo(List<IEncodableInfo> content)
  {
    Content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return Content.ToPrimitiveDerSequence();
  }
}