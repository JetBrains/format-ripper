using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class X500NameInfo : IEncodableInfo
{
  public string Name { get; }
  public List<List<RdNInfo>> RdNs { get; }

  public X500NameInfo(string name, List<List<RdNInfo>> rdNs)
  {
    Name = name;
    RdNs = rdNs;
  }

  public X500NameInfo(X509Name issuer)
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
      RdNs.Select(
        rdnList => rdnList.Cast<IEncodableInfo?>().ToList().ToPrimitiveList().ToDerSet()
      ).Cast<Asn1Encodable>().ToList()!.ToDerSequence();
  }

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}