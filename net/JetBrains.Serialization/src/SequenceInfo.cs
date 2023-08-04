using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class SequenceInfo : IEncodableInfo
{
  public readonly List<IEncodableInfo> Content;

  public SequenceInfo(List<IEncodableInfo> content)
  {
    Content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return Content.ToPrimitiveDerSequence();
  }
}