using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.OptIn)]
public class HolderInfo : IEncodableInfo
{
  [JsonProperty("BaseCertificateId")] private IssuerSerialInfo? _baseCertificateId;
  [JsonProperty("EntityName")] private List<GeneralNameInfo>? _entityName;
  [JsonProperty("ObjectDigestInfo")] private ObjectDigestInfo? _objectDigestInfo;
  [JsonProperty("Version")] private int _version;

  [JsonConstructor]
  public HolderInfo(
    IssuerSerialInfo? baseCertificateId,
    List<GeneralNameInfo>? entityName,
    ObjectDigestInfo? objectDigestInfo,
    int version
  )
  {
    _baseCertificateId = baseCertificateId;
    _entityName = entityName;
    _objectDigestInfo = objectDigestInfo;
    _version = version;
  }

  public HolderInfo(Holder holder)
  {
    _baseCertificateId = holder.BaseCertificateID != null ? new IssuerSerialInfo(holder.BaseCertificateID) : null;
    _entityName = holder.EntityName?.GetNames().Select(name => new GeneralNameInfo(name)).ToList();
    _objectDigestInfo = holder.ObjectDigestInfo != null ? new ObjectDigestInfo(holder.ObjectDigestInfo) : null;
    _version = holder.Version;
  }

  public Asn1Encodable ToPrimitive()
  {
    switch (_version)
    {
      case 0:
        if (_entityName == null)
        {
          return TaggedObjectInfo.GetTaggedObject(true, 0,
            _baseCertificateId?.ToPrimitive() ?? throw new InvalidOperationException());
        }

        return TaggedObjectInfo.GetTaggedObject(true, 1, _entityName.ToPrimitiveDerSequence());
      case 1:
        var items = new List<Asn1Encodable>();
        if (_baseCertificateId != null)
        {
          items.Add(TaggedObjectInfo.GetTaggedObject(false, 0, _baseCertificateId.ToPrimitive()));
        }

        if (_entityName != null)
        {
          items.Add(TaggedObjectInfo.GetTaggedObject(false, 1, _entityName.ToPrimitiveDerSequence()));
        }

        if (_objectDigestInfo != null)
        {
          items.Add(TaggedObjectInfo.GetTaggedObject(false, 2, _objectDigestInfo.ToPrimitive()));
        }

        return items.ToDerSequence();
      default:
        throw new ArgumentException($"Unexpected version {_version}");
    }
  }
}