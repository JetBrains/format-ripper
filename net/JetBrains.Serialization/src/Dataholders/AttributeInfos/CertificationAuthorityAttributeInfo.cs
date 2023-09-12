using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class CertificationAuthorityAttributeInfo : AttributeInfo
{
  [JsonProperty("Identifier")] protected override TextualInfo Identifier { get; }
  [JsonProperty("Content")] private List<AlgorithmInfo> _content;

  [JsonConstructor]
  public CertificationAuthorityAttributeInfo(TextualInfo identifier, List<AlgorithmInfo> content)
  {
    Identifier = identifier;
    _content = content;
  }

  public CertificationAuthorityAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    _content = attribute.AttrValues.ToArray().Select(item => new AlgorithmInfo(AlgorithmIdentifier.GetInstance(item)))
      .ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => _content.ToPrimitiveDerSet();
}