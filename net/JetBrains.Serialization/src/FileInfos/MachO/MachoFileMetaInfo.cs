using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.MachO;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.MachO;

[JsonObject(MemberSerialization.OptIn)]
public class MachoFileMetaInfo : IFileMetaInfo
{
  [JsonProperty("Metadata")] public MachoFileMetadata Metadata;

  [JsonConstructor]
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
      stream.Position = Metadata.CodeSignatureInfo.SuperBlobStart + Metadata.MachoOffset + blob.Offset;
      if (blob.Magic == CSMAGIC_CONSTS.CMS_SIGNATURE)
      {
        blob.Length = signature.Length + 8;
        blob.Content = signature;
      }

      if (blob.Type == (uint)CSMAGIC_CONSTS.CODEDIRECTORY)
      {
        stream.Write(blob.Content, 0, blob.Content.Length);
      }
      else
      {
        var blobBytes = blob.ToByteArray();
        stream.Write(blobBytes, 0, blobBytes.Length);
      }
    }
  }
}