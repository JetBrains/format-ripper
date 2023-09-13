namespace JetBrains.FormatRipper.Pe;

public class PeFileMetadata
{
  public DataValue CheckSum;
  public DataValue SecurityRva;
  public DataValue SecuritySize;
  public DataValue DwLength;
  public DataValue WRevision;
  public DataValue WCertificateType;
  public long SignaturePosition;

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