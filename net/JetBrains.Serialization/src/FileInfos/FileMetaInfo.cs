namespace JetBrains.Serialization.FileInfos;

public interface IFileMetaInfo
{
  void ModifyFile(Stream stream, byte[] signature);
}