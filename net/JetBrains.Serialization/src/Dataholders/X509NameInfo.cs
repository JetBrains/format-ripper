using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class X509NameInfo : IEncodableInfo
{
  [JsonProperty("Name")] private string _name;
  [JsonProperty("RdNs")] private List<List<RdNInfo>> _rdNs;

  [JsonConstructor]
  public X509NameInfo(string name, List<List<RdNInfo>> rdNs)
  {
    _name = name;
    _rdNs = rdNs;
  }

  public X509NameInfo(X509Name issuer)
    : this(issuer.ToString(),
      ((DerSequence)issuer.ToAsn1Object()).ToArray().OfType<DerSet>().Select(set =>
        set.ToArray().OfType<DerSequence>().Select(rdn =>
          new RdNInfo(TextualInfo.GetInstance(rdn[0]), TextualInfo.GetInstance(rdn[1]))).ToList()).ToList()
    )
  {
  }

  private DerSequence ToDLSequence()
  {
    return
      _rdNs.Select(
        rdnList => rdnList.ToPrimitiveDerSet()
      ).ToDerSequence();
  }

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}