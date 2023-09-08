using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.MachO;

namespace JetBrains.Serialization.FileInfos.MachO;

public class MachoFileMetaInfo : IFileMetaInfo
{
  public MachoFileMetadata Metadata;

  public MachoFileMetaInfo(MachoFileMetadata metadata)
  {
    Metadata = metadata;
  }

  public void ModifyFile(Stream stream, byte[] signature)
  {

    if (Metadata.FileSize > stream.Length)
    {
      stream.SetLength(Metadata.FileSize);
    }

    stream.Position = Metadata.MachoOffset;

    var headerBytes = Metadata.HeaderMetainfo.ToByteArray(Metadata.IsBe);

    stream.Write(headerBytes, 0, headerBytes.Length);

    foreach (var metadataLoadCommand in Metadata.LoadCommands)
    {
      stream.Position = metadataLoadCommand.Offset + Metadata.MachoOffset;
      var commandBytes = metadataLoadCommand.ToByteArray();
      stream.Write(commandBytes, 0, commandBytes.Length);
    }

    stream.Position = Metadata.CodeSignatureInfo.SuperBlobStart + Metadata.MachoOffset;
    var codeSignatureInfoBytes = Metadata.CodeSignatureInfo.ToByteArray();
    stream.Write(codeSignatureInfoBytes, 0, codeSignatureInfoBytes.Length);

    foreach (var blob in Metadata.CodeSignatureInfo.Blobs)
    {
      stream.Position = Metadata.CodeSignatureInfo.SuperBlobStart + Metadata.MachoOffset + blob.offset;
      if (blob.magic == CSMAGIC_CONSTS.CMS_SIGNATURE)
      {
        blob.length = signature.Length + 8;
        blob.content = signature;
      }

      if (blob.type == (uint)CSMAGIC_CONSTS.CODEDIRECTORY)
      {
        stream.Write(blob.content, 0, blob.content.Length);
      }
      else
      {
        var blobBytes = blob.ToByteArray();
        stream.Write(blobBytes, 0, blobBytes.Length);
      }
    }
  }
}