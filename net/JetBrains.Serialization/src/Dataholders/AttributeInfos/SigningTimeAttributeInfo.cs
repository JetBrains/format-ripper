using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Org.BouncyCastle.Asn1.Cms;

[JsonObject(MemberSerialization.Fields)]
public class SigningTimeAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<DateTimeOffset> Content { get; }
  private static readonly string DateTimeFormat = "yyMMddHHmmssZ";

  public SigningTimeAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item =>
      DateTimeOffset.ParseExact(item.ToString(), DateTimeFormat, CultureInfo.InvariantCulture)).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    Content.Select(time => new DerUtcTime(time.ToString(DateTimeFormat))).ToDerSet();
}