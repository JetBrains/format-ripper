using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Impl;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.Dmg;

[JsonObject(MemberSerialization.OptIn)]
public class DmgFileMetaInfo : IFileMetaInfo
{
  [JsonProperty("Metadata")] private DmgFileMetadata Metadata;

  [JsonConstructor]
  public DmgFileMetaInfo(DmgFileMetadata metadata)
  {
    Metadata = metadata;
  }

  public unsafe void ModifyFile(Stream stream, byte[] signature)
  {
    stream.Position = stream.Length - sizeof(UDIFResourceFile);
    byte[] unsignedUDIFResourceFileBytes = new byte[sizeof(UDIFResourceFile)];
    stream.Read(unsignedUDIFResourceFileBytes, 0, sizeof(UDIFResourceFile));

    if (Metadata.FileSize > stream.Length)
    {
      stream.Position = stream.Length;
      stream.Write(new byte[(int)(Metadata.FileSize - stream.Length)], 0,
        (int)(Metadata.FileSize - stream.Length));
    }

    stream.Position = Metadata.CodeSignaturePointer.Position;
    var codeSignatureInfoBytes = Metadata.CodeSignatureInfo.ToByteArray();
    stream.Write(codeSignatureInfoBytes, 0, codeSignatureInfoBytes.Length);

    foreach (var blob in Metadata.CodeSignatureInfo.Blobs)
    {
      stream.Position = Metadata.CodeSignatureInfo.SuperBlobStart + blob.Offset;

      blob.Length += 2 * sizeof(UInt32);

      if (blob.Magic == CSMAGIC_CONSTS.CMS_SIGNATURE)
      {
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

    stream.Position = stream.Length - sizeof(UDIFResourceFile);
    stream.Write(unsignedUDIFResourceFileBytes, 0, unsignedUDIFResourceFileBytes.Length);

    var codeSignaturePointerBytes = Metadata.CodeSignaturePointer.ToByteArray(isBe: true);
    stream.Position = stream.Length - sizeof(UDIFResourceFile) + DmgFile.CODE_SIGNATURE_POINTER_OFFSET;
    stream.Write(codeSignaturePointerBytes, 0, codeSignaturePointerBytes.Length);
  }
}