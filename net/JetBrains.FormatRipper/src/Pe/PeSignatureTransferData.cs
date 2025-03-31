namespace JetBrains.FormatRipper.Pe;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one PE file to another
/// </summary>
public class PeSignatureTransferData
{
  public uint CheckSum { get; set; }

  public uint TimeDateStamp { get; set; }

  public uint SignatureBlobOffset { get; set; }

  public uint SignatureBlobSize { get; set; }

  public ushort CertificateRevision { get; set; }

  public ushort CertificateType { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}