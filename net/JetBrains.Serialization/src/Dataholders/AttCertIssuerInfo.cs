using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.Fields)]
public class AttCertIssuerInfo : IEncodableInfo
{
    public List<GeneralNameInfo> IssuerName { get; set; }
    public IssuerSerialInfo? BaseCertificateId { get; set; }
    public ObjectDigestInfo? ObjectDigestInfo { get; set; }

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
            IssuerName.ToDerSequence(),
            BaseCertificateId?.ToPrimitive(),
            ObjectDigestInfo?.ToPrimitive()
        };

        return AttCertIssuer.GetInstance(V2Form.GetInstance(asn1Items.ToDerSequence())).ToAsn1Object();
    }
}