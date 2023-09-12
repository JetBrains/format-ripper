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
  [JsonProperty("IssuerName")] private List<GeneralNameInfo>? _issuerName;

  [JsonProperty("BaseCertificateId")] private IssuerSerialInfo? _baseCertificateId;

  [JsonProperty("ObjectDigestInfo")] private ObjectDigestInfo? _objectDigestInfo;

  [JsonConstructor]
  public AttCertIssuerInfo(List<GeneralNameInfo> issuerName, IssuerSerialInfo? baseCertificateId,
    ObjectDigestInfo? objectDigestInfo)
  {
    _issuerName = issuerName;
    _baseCertificateId = baseCertificateId;
    _objectDigestInfo = objectDigestInfo;
  }

  public AttCertIssuerInfo(AttCertIssuer issuer)
  {
    var v2Form = issuer.Issuer as V2Form;
    _issuerName = v2Form?.IssuerName.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
    _baseCertificateId = v2Form?.BaseCertificateID != null ? new IssuerSerialInfo(v2Form.BaseCertificateID) : null;
    _objectDigestInfo = v2Form?.ObjectDigestInfo != null ? new ObjectDigestInfo(v2Form.ObjectDigestInfo) : null;
  }

  public Asn1Encodable ToPrimitive()
  {
    var asn1Items = new List<Asn1Encodable?>
    {
      _issuerName?.ToPrimitiveDerSequence(),
      _baseCertificateId?.ToPrimitive(),
      _objectDigestInfo?.ToPrimitive()
    };

    return AttCertIssuer.GetInstance(V2Form.GetInstance(asn1Items.ToDerSequence())).ToAsn1Object();
  }
}