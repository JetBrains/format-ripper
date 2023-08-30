namespace JetBrains.Serialization.FileInfos.MachO;

public class MachoFileInfo : FileInfo
{
  public override IFileMetaInfo FileMetaInfo { get; }
  public override SignedDataInfo SignedDataInfo { get; }

  public override void ModifyFile(Stream stream)
  {
    FileMetaInfo.ModifyFile(stream, SignedDataInfo.ToSignature("BER"));
  }
}