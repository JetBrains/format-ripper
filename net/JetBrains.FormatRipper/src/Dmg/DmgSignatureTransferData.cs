namespace JetBrains.FormatRipper.Dmg;

/// <summary>
/// Interface that has sufficient information to transfer the signature from one DMG file to another
/// </summary>
public interface IDmgSignatureTransferData
{
  long SignatureOffset { get; }

  long SignatureLength { get; }

  byte[] SignatureBlob { get; }
}

internal class DmgSignatureTransferData: IDmgSignatureTransferData
{
  public long SignatureOffset { get; set; }

  public long SignatureLength { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}