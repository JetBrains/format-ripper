namespace JetBrains.FormatRipper.Dmg;

public class DmgFileMetadata
{
  public readonly long FileSize;
  public readonly StreamRange CodeSignaturePointer;
  public readonly CodeSignatureInfo CodeSignatureInfo;

  public DmgFileMetadata(long fileSize, StreamRange codeSignaturePointer, CodeSignatureInfo? codeSignatureInfo = null)
  {
    this.FileSize = fileSize;
    this.CodeSignaturePointer = codeSignaturePointer;
    this.CodeSignatureInfo = codeSignatureInfo ?? new CodeSignatureInfo();
  }
}