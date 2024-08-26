namespace JetBrains.FormatRipper.Pe;

/// <summary>
/// Class that stores sufficient information to transfer the signature from one PE file to another
/// </summary>
public class PeSignatureTransferData
{
  public uint CheckSum { get; internal set; }

  public uint TimeDateStamp { get; internal set; }

  public uint SignatureBlobOffset { get; internal set; }

  public uint SignatureBlobSize { get; internal set; }

  public ushort CertificateRevision { get; internal set; }

  public ushort CertificateType { get; internal set; }

  public byte[] SignatureBlob { get; internal set; } = null!;
}