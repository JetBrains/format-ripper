using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ObjectDigestInfo : IEncodableInfo
{
  [JsonProperty("DigestedObjectType")] public TextualInfo DigestedObjectType { get; set; }
  [JsonProperty("OtherObjectTypeID")] public TextualInfo? OtherObjectTypeID { get; set; }
  [JsonProperty("DigestAlgorithmInfo")] public AlgorithmInfo DigestAlgorithmInfo { get; set; }
  [JsonProperty("ObjectDigest")] public TextualInfo ObjectDigest { get; set; }

  [JsonConstructor]
  public ObjectDigestInfo(TextualInfo digestedObjectType, AlgorithmInfo digestAlgorithmInfo, TextualInfo objectDigest)
  {
    DigestedObjectType = digestedObjectType;
    DigestAlgorithmInfo = digestAlgorithmInfo;
    ObjectDigest = objectDigest;
  }

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