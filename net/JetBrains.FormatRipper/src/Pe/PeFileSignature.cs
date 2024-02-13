namespace JetBrains.FormatRipper.Pe;

public class PeFileSignature
{
  public uint ExpectedCrc { get; internal set; }

  public uint TimeDateStamp { get; internal set; }

  public uint SignatureBlobOffset { get; internal set; }

  public uint SignatureBlobSize { get; internal set; }

  public ushort CertificateRevision { get; internal set; }

  public ushort CertificateType { get; internal set; }

  public byte[] SignatureBlob { get; internal set; }
}