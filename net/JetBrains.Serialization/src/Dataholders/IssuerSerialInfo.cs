using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

[JsonObject(MemberSerialization.Fields)]
public class IssuerSerialInfo : IEncodableInfo
{
    public List<GeneralNameInfo> GeneralNames { get; set; }
    public BigInteger Serial { get; set; }
    public TextualInfo? IssuerUID { get; set; }

    public IssuerSerialInfo(IssuerSerial issuer)
    {
        GeneralNames = issuer.Issuer.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
        Serial = issuer.Serial.Value;
        IssuerUID = issuer.IssuerUid != null ? TextualInfo.GetInstance(issuer.IssuerUid) : null;
    }

    public Asn1Encodable ToPrimitive()
    {
        var asn1Items = new List<Asn1Encodable>
        {
            GeneralNames.ToDerSequence(),
            new DerInteger(Serial)
        };

        if (IssuerUID != null)
        {
            asn1Items.Add(IssuerUID.ToPrimitive());
        }

        return asn1Items.ToDerSequence();
    }
}