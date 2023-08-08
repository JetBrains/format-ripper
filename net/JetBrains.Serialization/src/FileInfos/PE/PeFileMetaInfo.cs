using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Pe;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.PE;

[JsonObject(MemberSerialization.OptIn)]
public class PeFileMetaInfo : IFileMetaInfo
{
  [JsonProperty("Metadata")] private PeFileMetadata Metadata { get; }

  [JsonConstructor]
  public PeFileMetaInfo(PeFileMetadata metadata)
  {
    Metadata = metadata;
  }

  public void ModifyFile(Stream stream, byte[] signature)
  {
    new List<DataValue>
    {
      Metadata.CheckSum,
      Metadata.SecurityRva,
      Metadata.SecuritySize,
      Metadata.DwLength,
      Metadata.WRevision,
      Metadata.WCertificateType,
    }.ForEach(
      it =>
      {
        stream.Position = it.Offset;
        stream.Write(it.Value!, 0, it.Value!.Length);
      }
    );

    stream.Position = Metadata.SignaturePosition;

    stream.Write(signature, 0, signature.Length);

    var alignment = (8 - stream.Position % 8) % 8;
    stream.Write(new byte[alignment], 0, (int)alignment);

    stream.Close();
  }
}