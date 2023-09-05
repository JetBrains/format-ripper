using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier.Crypt;

namespace JetBrains.Serialization.FileInfos.MachO;

public class MachoFileInfo : FileInfo
{
  public override IFileMetaInfo FileMetaInfo { get; }
  public override SignedDataInfo SignedDataInfo { get; }

  public MachoFileInfo(MachOFile.Section section)
  {
    var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
    SignedDataInfo = new SignedDataInfo(signedMessage.SignedData);
    if (section.Metadata == null)
      throw new Exception("Metadata can not be null");

    FileMetaInfo = new MachoFileMetaInfo(section.Metadata);
  }

  public override void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature("BER"));
  }
}