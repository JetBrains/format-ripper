using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.Fields)]
public class CertificationAuthorityAttributeInfo : AttributeInfo
{
  public override TextualInfo Identifier { get; }
  public List<AlgorithmInfo> Content { get; }

  public CertificationAuthorityAttributeInfo(Attribute attribute)
  {
    Identifier = TextualInfo.GetInstance(attribute.AttrType);
    Content = attribute.AttrValues.ToArray().Select(item => new AlgorithmInfo(AlgorithmIdentifier.GetInstance(item)))
      .ToList();
  }

  public override Asn1Encodable GetPrimitiveContent() => Content.ToPrimitiveDerSet();
}