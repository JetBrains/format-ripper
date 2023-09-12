using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.MachO;

[JsonObject(MemberSerialization.OptIn)]
public class MachoFileInfo : FileInfo
{
  [JsonProperty("FileMetaInfo")] public override IFileMetaInfo FileMetaInfo { get; }
  [JsonProperty("SignedDataInfo")] public override SignedDataInfo SignedDataInfo { get; }

  public MachoFileInfo(MachOFile.Section section)
  {
    var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
    SignedDataInfo = new SignedDataInfo(signedMessage.SignedData);
    if (section.Metadata == null)
      throw new Exception("Metadata can not be null");

    FileMetaInfo = new MachoFileMetaInfo(section.Metadata);
  }

  [JsonConstructor]
  public MachoFileInfo(IFileMetaInfo fileMetaInfo, SignedDataInfo signedDataInfo)
  {
    FileMetaInfo = fileMetaInfo;
    SignedDataInfo = signedDataInfo;
  }

  public override void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature("BER"));
  }
}