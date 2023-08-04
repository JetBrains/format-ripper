using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.Fields)]
public class GeneralNameInfo : IEncodableInfo
{
    public X509NameInfo Name { get; set; }
    public int Tag { get; set; }

    public GeneralNameInfo(GeneralName generalName)
    {
        Name = new X509NameInfo((X509Name) generalName.Name);
        Tag = generalName.TagNo;
    }

    public Asn1Encodable ToPrimitive()
    {
        return TaggedObjectInfo.GetTaggedObject(Tag == 4, Tag, Name.ToPrimitive());
    }
}