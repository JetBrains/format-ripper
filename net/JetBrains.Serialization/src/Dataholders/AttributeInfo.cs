using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public abstract class AttributeInfo : IEncodableInfo
{
  public abstract TextualInfo Identifier { get; }

  public abstract Asn1Encodable GetPrimitiveContent();

  public Asn1Encodable ToPrimitive() =>
    new List<Asn1Encodable?> { Identifier.ToPrimitive(), GetPrimitiveContent() }.ToDerSequence();

  public static AttributeInfo GetInstance(Attribute attribute)
  {
    switch (attribute.AttrType.Id)
    {
      // case "1.2.840.113549.1.9.3":
      //   return new ContentTypeAttributeInfo(attribute);
      // case "1.2.840.113549.1.9.4":
      //   return new MessageDigestAttributeInfo(attribute);
      // case "1.3.6.1.4.1.311.2.1.11":
      //   return new MSCertExtensionsAttributeInfo(attribute);
      // case "1.3.6.1.4.1.311.2.1.12":
      //   return new MSCertificateTemplateV2AttributeInfo(attribute);
      // case "1.3.6.1.4.1.311.10.3.28":
      //   return new TimestampedDataAttributeInfo(attribute);
      // case "1.2.840.113549.1.9.5":
      //   return new SigningTimeAttributeInfo(attribute);
      // case "1.2.840.113635.100.9.2":
      //   return new CertificationAuthorityAttributeInfo(attribute);
      // case "1.2.840.113549.1.9.6":
      //   return CounterSignatureAttributeInfo.GetInstance(attribute);
      case "1.2.840.113635.100.9.1":
        return new AppleDeveloperCertificateAttribute(attribute);
      case "1.3.6.1.4.1.311.3.3.1":
        return new MsCounterSignAttributeInfo(attribute);
      case "1.2.840.113549.1.9.52":
        return new CMSAlgorithmProtectionAttributeInfo(attribute);
      case "1.2.840.113549.1.9.16.2.47":
        return new V2CertificateAttributeInfo(attribute);
      case "1.2.840.113549.1.9.16.2.12":
        return new PublicKeyInfrastructureAttributeInfo(attribute);
      case "1.2.840.113549.1.9.16.2.14":
        return new SignatureTimeStampAttributeInfo(attribute);
      case "1.3.6.1.4.1.311.2.4.1":
        return new MSSpcNestedSignatureInfo(attribute);
      default:
        return new UnknownAttributeInfo(attribute);
    }
  }
}