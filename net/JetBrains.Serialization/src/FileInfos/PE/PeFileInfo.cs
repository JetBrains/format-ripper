using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.PE;

[JsonObject(MemberSerialization.OptIn)]
public class PeFileInfo : FileInfo
{
  [JsonProperty("fileMetaInfo")] public override IFileMetaInfo FileMetaInfo { get; }

  [JsonProperty("signedDataInfo")] public override SignedDataInfo SignedDataInfo { get; }

  [JsonConstructor]
  public PeFileInfo(IFileMetaInfo fileMetaInfo, SignedDataInfo signedDataInfo)
  {
    FileMetaInfo = fileMetaInfo;
    SignedDataInfo = signedDataInfo;
  }

  public PeFileInfo(PeFile peFile)
  {
    FileMetaInfo = new PeFileMetaInfo(peFile.FileMetadata ??
                                      throw new ArgumentNullException("peFile.FileMetadata",
                                        "FileMetadata can not be null"));

    SignedMessage signedMessage = SignedMessage.CreateInstance(peFile.SignatureData);

    var signedData = signedMessage.SignedData;

    SignedDataInfo = new SignedDataInfo(signedData);
  }
}