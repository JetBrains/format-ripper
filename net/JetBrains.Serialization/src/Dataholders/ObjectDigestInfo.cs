using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class ObjectDigestInfo : IEncodableInfo
{
  public TextualInfo DigestedObjectType { get; set; }
  public TextualInfo? OtherObjectTypeID { get; set; }
  public AlgorithmInfo DigestAlgorithmInfo { get; set; }
  public TextualInfo ObjectDigest { get; set; }

  public ObjectDigestInfo(Org.BouncyCastle.Asn1.X509.ObjectDigestInfo info)
  {
    DigestedObjectType = TextualInfo.GetInstance(info.DigestedObjectType);
    OtherObjectTypeID = info.OtherObjectTypeID != null ? TextualInfo.GetInstance(info.OtherObjectTypeID) : null;
    DigestAlgorithmInfo = new AlgorithmInfo(info.DigestAlgorithm);
    ObjectDigest = TextualInfo.GetInstance(info.ObjectDigest);
  }

  public Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo?>
    {
      DigestedObjectType,
      OtherObjectTypeID,
      DigestAlgorithmInfo,
      ObjectDigest
    }.ToPrimitiveDerSequence();
}