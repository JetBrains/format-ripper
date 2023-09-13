using JetBrains.FormatRipper.Dmg;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.Dmg;

[JsonObject(MemberSerialization.OptIn)]
public class DmgFileMetaInfo : IFileMetaInfo
{
  [JsonProperty("Metadata")] private DmgFileMetadata _metadata;

  [JsonConstructor]
  public DmgFileMetaInfo(DmgFileMetadata metadata)
  {
    _metadata = metadata;
  }

  public unsafe void ModifyFile(Stream stream, byte[] signature)
  {
    stream.Position = stream.Length - sizeof(UDIFResourceFile);
    byte[] unsignedUdifResourceFileBytes = new byte[sizeof(UDIFResourceFile)];
    stream.Read(unsignedUdifResourceFileBytes, 0, sizeof(UDIFResourceFile));

    if (_metadata.FileSize > stream.Length)
    {
      stream.Position = stream.Length;
      stream.Write(new byte[(int)(_metadata.FileSize - stream.Length)], 0,
        (int)(_metadata.FileSize - stream.Length));
    }

    stream.Position = _metadata.CodeSignaturePointer.Position;
    var codeSignatureInfoBytes = _metadata.CodeSignatureInfo.ToByteArray();
    stream.Write(codeSignatureInfoBytes, 0, codeSignatureInfoBytes.Length);

    foreach (var blob in _metadata.CodeSignatureInfo.Blobs)
    {
      stream.Position = _metadata.CodeSignatureInfo.SuperBlobStart + blob.Offset;

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
    stream.Write(unsignedUdifResourceFileBytes, 0, unsignedUdifResourceFileBytes.Length);

    var codeSignaturePointerBytes = _metadata.CodeSignaturePointer.ToByteArray(isBe: true);
    stream.Position = stream.Length - sizeof(UDIFResourceFile) + DmgFile.CODE_SIGNATURE_POINTER_OFFSET;
    stream.Write(codeSignaturePointerBytes, 0, codeSignaturePointerBytes.Length);
  }
}