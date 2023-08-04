using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class X509AttributeCertificateInfo : XCertificateInfo, IEncodableInfo
{
  [JsonProperty("Version")] public TextualInfo Version { get; set; }

  [JsonProperty("HolderInfo")] public HolderInfo HolderInfo { get; set; }

  [JsonProperty("Issuer")] public AttCertIssuerInfo Issuer { get; set; }

  [JsonProperty("SignatureInfo")] public AlgorithmInfo SignatureInfo { get; set; }

  [JsonProperty("SerialNumber")] public TextualInfo SerialNumber { get; set; }

  [JsonProperty("StartDate")] public DateTime StartDate { get; set; }

  [JsonProperty("EndDate")] public DateTime EndDate { get; set; }

  [JsonProperty("Attributes")] public List<AttributeInfo> Attributes { get; set; }

  [JsonProperty("IssuerUniqueId")] public TextualInfo? IssuerUniqueId { get; set; }

  [JsonProperty("Extensions")] public List<ExtensionInfo>? Extensions { get; set; }

  [JsonConstructor]
  public X509AttributeCertificateInfo(TextualInfo version, HolderInfo holderInfo, AttCertIssuerInfo issuer,
    AlgorithmInfo signatureInfo, TextualInfo serialNumber, DateTime startDate, DateTime endDate,
    List<AttributeInfo> attributes, TextualInfo? issuerUniqueId, List<ExtensionInfo>? extensions)
  {
    Version = version;
    HolderInfo = holderInfo;
    Issuer = issuer;
    SignatureInfo = signatureInfo;
    SerialNumber = serialNumber;
    StartDate = startDate;
    EndDate = endDate;
    Attributes = attributes;
    IssuerUniqueId = issuerUniqueId;
    Extensions = extensions;
  }

  public X509AttributeCertificateInfo()
  {
  }

  public static X509AttributeCertificateInfo GetInstance(AttributeCertificate attributeCertificate)
  {
    var acinfo = attributeCertificate.ACInfo;
    return new X509AttributeCertificateInfo
    {
      Version = TextualInfo.GetInstance(acinfo.Version),
      HolderInfo = new HolderInfo(acinfo.Holder),
      Issuer = new AttCertIssuerInfo(acinfo.Issuer),
      SignatureInfo = new AlgorithmInfo(acinfo.Signature),
      SerialNumber = TextualInfo.GetInstance(acinfo.SerialNumber),
      StartDate = acinfo.AttrCertValidityPeriod.NotBeforeTime.ToDateTime(),
      EndDate = acinfo.AttrCertValidityPeriod.NotAfterTime.ToDateTime(),
      Attributes = acinfo.Attributes.ToArray().Select(it => AttributeInfo.GetInstance(Attribute.GetInstance(it)))
        .ToList(),
      IssuerUniqueId = acinfo.IssuerUniqueID != null ? TextualInfo.GetInstance(acinfo.IssuerUniqueID) : null,
      Extensions = acinfo.Extensions != null
        ? acinfo.Extensions.ExtensionOids.OfType<DerObjectIdentifier>().ToArray().Select(oid =>
        {
          var extension = acinfo.Extensions.GetExtension(oid);
          return new ExtensionInfo(
            TextualInfo.GetInstance(oid),
            extension.IsCritical,
            TextualInfo.GetInstance(extension.Value)
          );
        }).ToList()
        : null
    };
  }

  public override Asn1Encodable ToPrimitive()
  {
    var asn1List = new List<Asn1Encodable>
    {
      Version.ToPrimitive(),
      HolderInfo.ToPrimitive(),
      Issuer.ToPrimitive(),
      SignatureInfo.ToPrimitive(),
      SerialNumber.ToPrimitive(),
      new AttCertValidityPeriod(
        new DerGeneralizedTime(StartDate),
        new DerGeneralizedTime(EndDate)
      ),
      Attributes.ToPrimitiveDerSequence()
    };

    if (IssuerUniqueId != null)
    {
      asn1List.Add(IssuerUniqueId.ToPrimitive());
    }

    if (Extensions != null && Extensions.Any())
    {
      asn1List.Add(Extensions.ToPrimitiveDerSequence());
    }

    return asn1List.ToDerSequence();
  }
}