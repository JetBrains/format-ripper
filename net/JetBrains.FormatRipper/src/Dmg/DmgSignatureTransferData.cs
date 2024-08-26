namespace JetBrains.FormatRipper.Dmg;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one DMG file to another
/// </summary>
public class DmgSignatureTransferData
{
  public long SignatureOffset { get; internal set; }

  public long SignatureLength { get; internal set; }

  public byte[] SignatureBlob { get; internal set; } = null!;
}