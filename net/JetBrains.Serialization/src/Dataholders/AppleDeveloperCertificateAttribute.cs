using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using System.Collections.Generic;

[JsonObject(MemberSerialization.OptIn)]
public class AppleDeveloperCertificateAttribute : AttributeInfo
{
  [JsonProperty("Identifier")] public override TextualInfo Identifier { get; }

  [JsonProperty("Content")] public List<TextualInfo> Content { get; }

  [JsonConstructor]
  public AppleDeveloperCertificateAttribute(TextualInfo identifier, List<TextualInfo> content)
  {
    Identifier = identifier;
    Content = content;
  }

  public AppleDeveloperCertificateAttribute(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => TextualInfo.GetInstance(item)).ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}