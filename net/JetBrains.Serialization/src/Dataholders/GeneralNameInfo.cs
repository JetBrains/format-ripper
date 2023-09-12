using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class GeneralNameInfo : IEncodableInfo
{
  [JsonProperty("Name")] private X509NameInfo _name;

  [JsonProperty("Tag")] private int _tag;

  [JsonConstructor]
  public GeneralNameInfo(X509NameInfo name, int tag)
  {
    _name = name;
    _tag = tag;
  }

  public GeneralNameInfo(GeneralName generalName)
  {
    _name = new X509NameInfo((X509Name)generalName.Name);
    _tag = generalName.TagNo;
  }

  public Asn1Encodable ToPrimitive()
  {
    return TaggedObjectInfo.GetTaggedObject(_tag == 4, _tag, _name.ToPrimitive());
  }
}