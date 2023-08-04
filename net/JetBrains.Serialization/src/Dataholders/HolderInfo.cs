using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using JetBrains.Serialization;
using Org.BouncyCastle.Asn1.X509;

[JsonObject(MemberSerialization.Fields)]
public class HolderInfo : IEncodableInfo
{
    public IssuerSerialInfo? BaseCertificateId { get; set; }
    public List<GeneralNameInfo>? EntityName { get; set; }
    public ObjectDigestInfo? ObjectDigestInfo { get; set; }
    public int Version { get; set; }

    public HolderInfo(Holder holder)
    {
        BaseCertificateId = holder.BaseCertificateID != null ? new IssuerSerialInfo(holder.BaseCertificateID) : null;
        EntityName = holder.EntityName != null ? holder.EntityName.GetNames().Select(name => new GeneralNameInfo(name)).ToList() : null;
        ObjectDigestInfo = holder.ObjectDigestInfo != null ? new ObjectDigestInfo(holder.ObjectDigestInfo) : null;
        Version = holder.Version;
    }

    public Asn1Encodable ToPrimitive()
    {
      switch (Version)
      {
        case 0:
          if (EntityName == null)
          {
            return TaggedObjectInfo.GetTaggedObject(true, 0, BaseCertificateId?.ToPrimitive());
          }

          return TaggedObjectInfo.GetTaggedObject(true, 1, EntityName.ToPrimitiveDerSequence());
        case 1:
          var items = new List<Asn1Encodable>();
          if (BaseCertificateId != null)
          {
            items.Add(TaggedObjectInfo.GetTaggedObject(false, 0, BaseCertificateId.ToPrimitive()));
          }

          if (EntityName != null)
          {
            items.Add(TaggedObjectInfo.GetTaggedObject(false, 1, EntityName.ToPrimitiveDerSequence()));
          }

          if (ObjectDigestInfo != null)
          {
            items.Add(TaggedObjectInfo.GetTaggedObject(false, 2, ObjectDigestInfo.ToPrimitive()));
          }

          return items.ToDerSequence();
        default:
          throw new ArgumentException($"Unexpected version {Version}");
      }
    }
}