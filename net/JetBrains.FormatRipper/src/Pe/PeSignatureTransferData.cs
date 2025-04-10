namespace JetBrains.FormatRipper.Pe;

/// <summary>
/// Interface that has sufficient information to transfer the signature from one PE file to another
/// </summary>
public interface IPeSignatureTransferData
{
  uint CheckSum { get; }

  uint TimeDateStamp { get; }

  uint SignatureBlobOffset { get; }

  uint SignatureBlobSize { get; }

  ushort CertificateRevision { get; }

  ushort CertificateType { get; }

  byte[] SignatureBlob { get; }
}

internal class PeSignatureTransferData: IPeSignatureTransferData
{
  public uint CheckSum { get; set; }

  public uint TimeDateStamp { get; set; }

  public uint SignatureBlobOffset { get; set; }

  public uint SignatureBlobSize { get; set; }

  public ushort CertificateRevision { get; set; }

  public ushort CertificateType { get; set; }

  public byte[] SignatureBlob { get; set; } = null!;
}