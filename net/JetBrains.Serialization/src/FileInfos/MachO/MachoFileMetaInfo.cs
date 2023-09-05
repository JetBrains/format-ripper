using JetBrains.FormatRipper.MachO;

namespace JetBrains.Serialization.FileInfos.MachO;

public class MachoFileMetaInfo: IFileMetaInfo
{
  public MachoFileMetaInfo(MachoFileMetadata metadata)
  {

  }

  public void ModifyFile(Stream stream, byte[] signature)
  {
    throw new NotImplementedException();
  }
}