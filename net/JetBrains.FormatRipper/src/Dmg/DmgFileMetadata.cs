namespace JetBrains.FormatRipper.Dmg;

public class DmgFileMetadata
{
  public readonly long fileSize;
  public readonly StreamRange codeSignaturePointer;
  public readonly CodeSignatureInfo codeSignatureInfo = new CodeSignatureInfo();

  public DmgFileMetadata(long fileSize, StreamRange codeSignaturePointer)
  {
    this.fileSize = fileSize;
    this.codeSignaturePointer = codeSignaturePointer;
  }
}