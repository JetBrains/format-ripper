using JetBrains.FormatRipper;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.Serialization.FileInfos.Dmg;

public class DmgFileMetaInfo : IFileMetaInfo
{
  private DmgFileMetadata Metadata;

  public DmgFileMetaInfo(DmgFileMetadata metadata)
  {
    Metadata = metadata;
  }

  public unsafe void ModifyFile(Stream stream, byte[] signature)
  {
    stream.Position = stream.Length - sizeof(UDIFResourceFile);
    byte[] unsignedUDIFResourceFileBytes = new byte[sizeof(UDIFResourceFile)];
    stream.Read(unsignedUDIFResourceFileBytes, 0, sizeof(UDIFResourceFile));

    if (Metadata.fileSize > stream.Length)
    {
      stream.Position = stream.Length;
      stream.Write(new byte[(int)(Metadata.fileSize - stream.Length)], 0,
        (int)(Metadata.fileSize - stream.Length));
    }

    stream.Position = Metadata.codeSignaturePointer.Position;
    var codeSignatureInfoBytes = Metadata.codeSignatureInfo.ToByteArray();
    stream.Write(codeSignatureInfoBytes, 0, codeSignatureInfoBytes.Length);

    foreach (var blob in Metadata.codeSignatureInfo.blobs)
    {
      stream.Position = Metadata.codeSignatureInfo.superBlobStart + blob.offset;

      blob.length += 2 * sizeof(UInt32);

      if (blob.magic == CSMAGIC_CONSTS.CMS_SIGNATURE)
      {
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

    stream.Position = stream.Length - sizeof(UDIFResourceFile);
    stream.Write(unsignedUDIFResourceFileBytes, 0, unsignedUDIFResourceFileBytes.Length);

    var codeSignaturePointerBytes = Metadata.codeSignaturePointer.ToByteArray(isBE: true);
    stream.Position = stream.Length - sizeof(UDIFResourceFile) + DmgFile.CodeSignaturePointerOffset;
    stream.Write(codeSignaturePointerBytes, 0, codeSignaturePointerBytes.Length);
  }
}