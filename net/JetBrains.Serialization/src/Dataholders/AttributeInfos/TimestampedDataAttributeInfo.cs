using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System.Collections.Generic;
using System.Linq;

[JsonObject(MemberSerialization.OptIn)]
public class TimestampedDataAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public List<TextualInfo> Content { get; }

  [JsonConstructor]
  public TimestampedDataAttributeInfo(TextualInfo identifier, List<TextualInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public TimestampedDataAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => TextualInfo.GetInstance(item)).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}