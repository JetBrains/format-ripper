using JetBrains.FormatRipper.Dmg;
using JetBrains.SignatureVerifier.Crypt;

namespace JetBrains.Serialization.FileInfos.Dmg;

public class DmgFileInfo : FileInfo
{
  public DmgFileInfo(DmgFile file)
  {
    FileMetaInfo = new DmgFileMetaInfo(file.Metadata);
    SignedMessage signedMessage = SignedMessage.CreateInstance(file.SignatureData.Value);

    var signedData = signedMessage.SignedData;

    SignedDataInfo = new SignedDataInfo(signedData);
  }

  public override IFileMetaInfo FileMetaInfo { get; }
  public override SignedDataInfo SignedDataInfo { get; }

  public override void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature("BER"));
  }
}