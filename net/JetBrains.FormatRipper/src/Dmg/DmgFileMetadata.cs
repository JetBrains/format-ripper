namespace JetBrains.FormatRipper.Dmg;

public class DmgFileMetadata
{
  public readonly long fileSize;
  public readonly StreamRange codeSignaturePointer;
  public readonly CodeSignatureInfo codeSignatureInfo;

  public DmgFileMetadata(long fileSize, StreamRange codeSignaturePointer, CodeSignatureInfo? codeSignatureInfo = null)
  {
    this.fileSize = fileSize;
    this.codeSignaturePointer = codeSignaturePointer;
    this.codeSignatureInfo = codeSignatureInfo ?? new CodeSignatureInfo();
  }
}