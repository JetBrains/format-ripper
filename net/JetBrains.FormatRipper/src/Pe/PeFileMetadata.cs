namespace JetBrains.FormatRipper.Pe;

public class PeFileMetadata
{
  public DataValue CheckSum { get; set; }
  public DataValue SecurityRva { get; set; }
  public DataValue SecuritySize { get; set; }
  public DataValue DwLength { get; set; }
  public DataValue WRevision { get; set; }
  public DataValue WCertificateType { get; set; }
  public long SignaturePosition { get; set; }

  public PeFileMetadata(
    DataValue? checkSum = null,
    DataValue? securityRva = null,
    DataValue? securitySize = null,
    DataValue? dwLength = null,
    DataValue? wRevision = null,
    DataValue? wCertificateType = null,
    long signaturePosition = 0)
  {
    CheckSum = checkSum ?? new DataValue();
    SecurityRva = securityRva ?? new DataValue();
    SecuritySize = securitySize ?? new DataValue();
    DwLength = dwLength ?? new DataValue();
    WRevision = wRevision ?? new DataValue();
    WCertificateType = wCertificateType ?? new DataValue();
    SignaturePosition = signaturePosition;
  }
}