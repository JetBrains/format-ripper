using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos;

[JsonObject(MemberSerialization.OptIn)]
public abstract class FileInfo
{
  [JsonProperty("fileMetaInfo")]
  public abstract IFileMetaInfo FileMetaInfo { get; }

  [JsonProperty("signedDataInfo")]
  public abstract SignedDataInfo SignedDataInfo { get; }

  public virtual void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature());
  }
}