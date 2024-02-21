namespace JetBrains.FormatRipper.Dmg;

public class DmgFileSignature
{
  public long SignatureOffset { get; internal set; }

  public long SignatureLength { get; internal set; }

  public byte[] SignatureBlob { get; internal set; }
}