using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class GeneralNameInfo : IEncodableInfo
{
  [JsonProperty("Name")] public X509NameInfo Name { get; set; }

  [JsonProperty("Tag")] public int Tag { get; set; }

  [JsonConstructor]
  public GeneralNameInfo(X509NameInfo name, int tag)
  {
    Name = name;
    Tag = tag;
  }

  public GeneralNameInfo(GeneralName generalName)
  {
    Name = new X509NameInfo((X509Name)generalName.Name);
    Tag = generalName.TagNo;
  }

  public Asn1Encodable ToPrimitive()
  {
    return TaggedObjectInfo.GetTaggedObject(Tag == 4, Tag, Name.ToPrimitive());
  }
}