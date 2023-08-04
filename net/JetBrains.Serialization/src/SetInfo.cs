using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class SetInfo : IEncodableInfo
{
  private readonly List<IEncodableInfo> _content;

  public SetInfo(List<IEncodableInfo> content)
  {
    _content = content;
  }

  public Asn1Encodable ToPrimitive()
  {
    return _content.ToDerSet();
  }
}