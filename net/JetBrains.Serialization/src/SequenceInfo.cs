using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class SequenceInfo : IEncodableInfo
{
  private readonly List<IEncodableInfo> _content;

  public SequenceInfo(List<IEncodableInfo> content)
  {
    _content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return _content.ToPrimitiveList().ToDerSequence();
  }
}