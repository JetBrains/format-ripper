using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class X509AttributeCertificateInfo : XCertificateInfo, IEncodableInfo
{
  [JsonProperty("Version")] private TextualInfo _version;
  [JsonProperty("HolderInfo")] private HolderInfo _holderInfo;
  [JsonProperty("Issuer")] private AttCertIssuerInfo _issuer;
  [JsonProperty("SignatureInfo")] private AlgorithmInfo _signatureInfo;
  [JsonProperty("SerialNumber")] private TextualInfo _serialNumber;
  [JsonProperty("StartDate")] private DateTime _startDate;
  [JsonProperty("EndDate")] private DateTime _endDate;
  [JsonProperty("Attributes")] private List<AttributeInfo> _attributes;
  [JsonProperty("IssuerUniqueId")] private TextualInfo? _issuerUniqueId;
  [JsonProperty("Extensions")] private List<ExtensionInfo>? _extensions;

  [JsonConstructor]
  public X509AttributeCertificateInfo(TextualInfo version, HolderInfo holderInfo, AttCertIssuerInfo issuer,
    AlgorithmInfo signatureInfo, TextualInfo serialNumber, DateTime startDate, DateTime endDate,
    List<AttributeInfo> attributes, TextualInfo? issuerUniqueId, List<ExtensionInfo>? extensions)
  {
    _version = version;
    _holderInfo = holderInfo;
    _issuer = issuer;
    _signatureInfo = signatureInfo;
    _serialNumber = serialNumber;
    _startDate = startDate;
    _endDate = endDate;
    _attributes = attributes;
    _issuerUniqueId = issuerUniqueId;
    _extensions = extensions;
  }

  private X509AttributeCertificateInfo()
  {
  }

  public static X509AttributeCertificateInfo GetInstance(AttributeCertificate attributeCertificate)
  {
    var attributeCertificateAcInfo = attributeCertificate.ACInfo;
    return new X509AttributeCertificateInfo
    {
      _version = TextualInfo.GetInstance(attributeCertificateAcInfo.Version),
      _holderInfo = new HolderInfo(attributeCertificateAcInfo.Holder),
      _issuer = new AttCertIssuerInfo(attributeCertificateAcInfo.Issuer),
      _signatureInfo = new AlgorithmInfo(attributeCertificateAcInfo.Signature),
      _serialNumber = TextualInfo.GetInstance(attributeCertificateAcInfo.SerialNumber),
      _startDate = attributeCertificateAcInfo.AttrCertValidityPeriod.NotBeforeTime.ToDateTime(),
      _endDate = attributeCertificateAcInfo.AttrCertValidityPeriod.NotAfterTime.ToDateTime(),
      _attributes = attributeCertificateAcInfo.Attributes.ToArray()
        .Select(it => AttributeInfo.GetInstance(Attribute.GetInstance(it)))
        .ToList(),
      _issuerUniqueId = attributeCertificateAcInfo.IssuerUniqueID != null
        ? TextualInfo.GetInstance(attributeCertificateAcInfo.IssuerUniqueID)
        : null,
      _extensions = attributeCertificateAcInfo.Extensions?.ExtensionOids.OfType<DerObjectIdentifier>().ToArray().Select(
        oid =>
        {
          var extension = attributeCertificateAcInfo.Extensions.GetExtension(oid);
          return new ExtensionInfo(
            TextualInfo.GetInstance(oid),
            extension.IsCritical,
            TextualInfo.GetInstance(extension.Value)
          );
        }).ToList()
    };
  }

  public override Asn1Encodable ToPrimitive()
  {
    var asn1List = new List<Asn1Encodable>
    {
      _version.ToPrimitive(),
      _holderInfo.ToPrimitive(),
      _issuer.ToPrimitive(),
      _signatureInfo.ToPrimitive(),
      _serialNumber.ToPrimitive(),
      new AttCertValidityPeriod(
        new DerGeneralizedTime(_startDate),
        new DerGeneralizedTime(_endDate)
      ),
      _attributes.ToPrimitiveDerSequence()
    };

    if (_issuerUniqueId != null)
    {
      asn1List.Add(_issuerUniqueId.ToPrimitive());
    }

    if (_extensions != null && _extensions.Any())
    {
      asn1List.Add(_extensions.ToPrimitiveDerSequence());
    }

    return asn1List.ToDerSequence();
  }
}