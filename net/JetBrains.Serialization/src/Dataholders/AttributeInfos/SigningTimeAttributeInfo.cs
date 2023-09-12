using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System.Globalization;

[JsonObject(MemberSerialization.OptIn)]
public class SigningTimeAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }

  [JsonProperty("Content")] private List<DateTimeOffset> _content;
  private static readonly string DateTimeFormat = "yyMMddHHmmssZ";

  [JsonConstructor]
  public SigningTimeAttributeInfo(TextualInfo identifier, List<DateTimeOffset> content)
  {
    Identifier = identifier;
    _content = content;
  }

  public SigningTimeAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    _content = attribute.AttrValues.ToArray().Select(item =>
      DateTimeOffset.ParseExact(item.ToString(), DateTimeFormat, CultureInfo.InvariantCulture)).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() =>
    _content.Select(time => new DerUtcTime(time.ToString(DateTimeFormat))).ToDerSet();
}