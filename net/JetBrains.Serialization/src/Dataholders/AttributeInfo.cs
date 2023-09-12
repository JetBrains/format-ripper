using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public abstract class AttributeInfo : IEncodableInfo
{
  [JsonProperty("Identifier")] protected abstract TextualInfo Identifier { get; }

  public abstract Asn1Encodable GetPrimitiveContent();

  public Asn1Encodable ToPrimitive() =>
    new List<Asn1Encodable?> { Identifier.ToPrimitive(), GetPrimitiveContent() }.ToDerSequence();

  private static readonly Dictionary<string, Func<Attribute, AttributeInfo>> AttributeTypeMappings =
    new()
    {
      { "1.2.840.113549.1.9.3", a => new ContentTypeAttributeInfo(a) },
      { "1.2.840.113549.1.9.4", a => new MessageDigestAttributeInfo(a) },
      { "1.3.6.1.4.1.311.2.1.11", a => new MSCertExtensionsAttributeInfo(a) },
      { "1.3.6.1.4.1.311.2.1.12", a => new MSCertificateTemplateV2AttributeInfo(a) },
      { "1.3.6.1.4.1.311.10.3.28", a => new TimestampedDataAttributeInfo(a) },
      { "1.2.840.113549.1.9.5", a => new SigningTimeAttributeInfo(a) },
      { "1.2.840.113635.100.9.2", a => new CertificationAuthorityAttributeInfo(a) },
      { "1.2.840.113549.1.9.6", a => new CounterSignatureAttributeInfo(a) },
      { "1.2.840.113635.100.9.1", a => new AppleDeveloperCertificateAttribute(a) },
      { "1.3.6.1.4.1.311.3.3.1", a => new MsCounterSignAttributeInfo(a) },
      { "1.2.840.113549.1.9.52", a => new CMSAlgorithmProtectionAttributeInfo(a) },
      { "1.2.840.113549.1.9.16.2.47", a => new V2CertificateAttributeInfo(a) },
      { "1.2.840.113549.1.9.16.2.12", a => new PublicKeyInfrastructureAttributeInfo(a) },
      { "1.2.840.113549.1.9.16.2.14", a => new SignatureTimeStampAttributeInfo(a) },
      { "1.3.6.1.4.1.311.2.4.1", a => new MSSpcNestedSignatureInfo(a) },
    };

  public static AttributeInfo GetInstance(Attribute attribute)
  {
    var attributeId = attribute.AttrType.Id;

    if (AttributeTypeMappings.TryGetValue(attributeId, out var constructor))
      return constructor(attribute);

    return new UnknownAttributeInfo(attribute);
  }
}