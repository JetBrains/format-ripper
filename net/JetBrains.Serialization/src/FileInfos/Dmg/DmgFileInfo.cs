using JetBrains.FormatRipper.Dmg;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.Dmg;

[JsonObject(MemberSerialization.OptIn)]
public class DmgFileInfo : FileInfo
{
  [JsonProperty("fileMetaInfo")] public override IFileMetaInfo FileMetaInfo { get; }

  [JsonProperty("signedDataInfo")] public override SignedDataInfo SignedDataInfo { get; }

  public DmgFileInfo(DmgFile file)
  {
    FileMetaInfo = new DmgFileMetaInfo(file.Metadata);
    if (file.SignatureData() == null)
      throw new Exception("Signature data is empty");

    SignedMessage signedMessage = SignedMessage.CreateInstance(file.SignatureData()!.Value);

    var signedData = signedMessage.SignedData;

    SignedDataInfo = new SignedDataInfo(signedData);
  }

  [JsonConstructor]
  public DmgFileInfo(IFileMetaInfo fileMetaInfo, SignedDataInfo signedDataInfo)
  {
    FileMetaInfo = fileMetaInfo;
    SignedDataInfo = signedDataInfo;
  }

  public override void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature("BER"));
  }
}