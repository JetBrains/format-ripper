using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class ObjectDigestInfo : IEncodableInfo
{
  [JsonProperty("DigestedObjectType")] private TextualInfo _digestedObjectType;
  [JsonProperty("OtherObjectTypeID")] private TextualInfo? _otherObjectTypeId;
  [JsonProperty("DigestAlgorithmInfo")] private AlgorithmInfo _digestAlgorithmInfo;
  [JsonProperty("ObjectDigest")] private TextualInfo _objectDigest;

  [JsonConstructor]
  public ObjectDigestInfo(TextualInfo digestedObjectType, AlgorithmInfo digestAlgorithmInfo, TextualInfo objectDigest,
    TextualInfo? otherObjectTypeId)
  {
    _digestedObjectType = digestedObjectType;
    _digestAlgorithmInfo = digestAlgorithmInfo;
    _objectDigest = objectDigest;
    _otherObjectTypeId = otherObjectTypeId;
  }

  public ObjectDigestInfo(Org.BouncyCastle.Asn1.X509.ObjectDigestInfo info)
  {
    _digestedObjectType = TextualInfo.GetInstance(info.DigestedObjectType);
    _otherObjectTypeId = info.OtherObjectTypeID != null ? TextualInfo.GetInstance(info.OtherObjectTypeID) : null;
    _digestAlgorithmInfo = new AlgorithmInfo(info.DigestAlgorithm);
    _objectDigest = TextualInfo.GetInstance(info.ObjectDigest);
  }

  public Asn1Encodable ToPrimitive() =>
    new List<IEncodableInfo?>
    {
      _digestedObjectType,
      _otherObjectTypeId,
      _digestAlgorithmInfo,
      _objectDigest
    }.ToPrimitiveDerSequence();
}