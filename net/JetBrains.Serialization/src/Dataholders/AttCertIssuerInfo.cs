using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.Linq;

[JsonObject(MemberSerialization.OptIn)]
public class AttCertIssuerInfo : IEncodableInfo
{
  [JsonProperty("IssuerName")] public List<GeneralNameInfo> IssuerName { get; set; }

  [JsonProperty("BaseCertificateId")] public IssuerSerialInfo? BaseCertificateId { get; set; }

  [JsonProperty("ObjectDigestInfo")] public ObjectDigestInfo? ObjectDigestInfo { get; set; }

  [JsonConstructor]
  public AttCertIssuerInfo(List<GeneralNameInfo> issuerName, IssuerSerialInfo? baseCertificateId,
    ObjectDigestInfo? objectDigestInfo)
  {
    IssuerName = issuerName;
    BaseCertificateId = baseCertificateId;
    ObjectDigestInfo = objectDigestInfo;
  }

  public AttCertIssuerInfo(AttCertIssuer issuer)
  {
    var v2Form = issuer.Issuer as V2Form;
    IssuerName = v2Form?.IssuerName.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
    BaseCertificateId = v2Form?.BaseCertificateID != null ? new IssuerSerialInfo(v2Form.BaseCertificateID) : null;
    ObjectDigestInfo = v2Form?.ObjectDigestInfo != null ? new ObjectDigestInfo(v2Form.ObjectDigestInfo) : null;
  }

  public Asn1Encodable ToPrimitive()
  {
    var asn1Items = new List<Asn1Encodable?>
    {
      IssuerName.ToPrimitiveDerSequence(),
      BaseCertificateId?.ToPrimitive(),
      ObjectDigestInfo?.ToPrimitive()
    };

    return AttCertIssuer.GetInstance(V2Form.GetInstance(asn1Items.ToDerSequence())).ToAsn1Object();
  }
}