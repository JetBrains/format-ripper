using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace JetBrains.Serialization;

using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class X509AttributeCertificateInfo : XCertificateInfo, IEncodableInfo
{
  public BigInteger Version { get; set; }

  public HolderInfo HolderInfo { get; set; }

  public AttCertIssuerInfo Issuer { get; set; }

  public AlgorithmInfo SignatureInfo { get; set; }

  public BigInteger SerialNumber { get; set; }

  public DateTime StartDate { get; set; }

  public DateTime EndDate { get; set; }

  public List<AttributeInfo> Attributes { get; set; }

  public TextualInfo? IssuerUniqueId { get; set; }

  public List<ExtensionInfo>? Extensions { get; set; }

  public static X509AttributeCertificateInfo GetInstance(AttributeCertificate attributeCertificate)
  {
    var acinfo = attributeCertificate.ACInfo;
    return new X509AttributeCertificateInfo
    {
      Version = acinfo.Version.Value,
      HolderInfo = new HolderInfo(acinfo.Holder),
      Issuer = new AttCertIssuerInfo(acinfo.Issuer),
      SignatureInfo = new AlgorithmInfo(acinfo.Signature),
      SerialNumber = acinfo.SerialNumber.Value,
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
      new DerInteger(Version),
      HolderInfo.ToPrimitive(),
      Issuer.ToPrimitive(),
      SignatureInfo.ToPrimitive(),
      new DerInteger(SerialNumber),
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