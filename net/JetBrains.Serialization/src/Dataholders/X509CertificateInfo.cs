using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class X509CertificateInfo : XCertificateInfo
{
  [JsonProperty("Version")] private int _version;
  [JsonProperty("SerialNumber")] private TextualInfo _serialNumber;
  [JsonProperty("SignatureAlgorithm")] private AlgorithmInfo _signatureAlgorithm;
  [JsonProperty("Issuer")] private X509NameInfo _issuer;
  [JsonProperty("StartDate")] private DateTime _startDate;
  [JsonProperty("EndDate")] private DateTime _endDate;
  [JsonProperty("Subject")] private X509NameInfo _subject;
  [JsonProperty("SubjectAlgorithm")] private AlgorithmInfo _subjectAlgorithm;
  [JsonProperty("SubjectData")] private TextualInfo _subjectData;
  [JsonProperty("Extensions")] private List<ExtensionInfo>? _extensions;

  [JsonConstructor]
  public X509CertificateInfo(
    int version,
    TextualInfo serialNumber,
    AlgorithmInfo signatureAlgorithm,
    X509NameInfo issuer,
    DateTime startDate,
    DateTime endDate,
    X509NameInfo subject,
    AlgorithmInfo subjectAlgorithm,
    TextualInfo subjectData,
    List<ExtensionInfo>? extensions)
  {
    _version = version;
    _serialNumber = serialNumber;
    _signatureAlgorithm = signatureAlgorithm;
    _issuer = issuer;
    _startDate = startDate;
    _endDate = endDate;
    _subject = subject;
    _subjectAlgorithm = subjectAlgorithm;
    _subjectData = subjectData;
    _extensions = extensions;
  }

  public static X509CertificateInfo GetInstance(TbsCertificateStructure certificateHolder)
  {
    return new X509CertificateInfo(
      certificateHolder.Version,
      TextualInfo.GetInstance(certificateHolder.SerialNumber),
      new AlgorithmInfo(certificateHolder.Signature),
      new X509NameInfo(certificateHolder.Issuer),
      certificateHolder.StartDate.ToDateTime(),
      certificateHolder.EndDate.ToDateTime(),
      new X509NameInfo(certificateHolder.Subject),
      new AlgorithmInfo(certificateHolder.SubjectPublicKeyInfo.AlgorithmID),
      TextualInfo.GetInstance(certificateHolder.SubjectPublicKeyInfo.PublicKeyData),
      certificateHolder.Extensions?.ExtensionOids.OfType<DerObjectIdentifier>().ToList().Select(oid =>
      {
        var extension = certificateHolder.Extensions.GetExtension(oid);
        return new ExtensionInfo(
          TextualInfo.GetInstance(oid),
          extension.IsCritical,
          TextualInfo.GetInstance(extension.Value));
      }).ToList()
    );
  }

  // However, ASN1Integer, DLSequence, DLTaggedObjects and such are from BouncyCastle's ASN1 libraries.
  // So, be sure to include an appropriate library which can handle these structures.
  private DerSequence ToDLSequence() =>
    new List<Asn1Encodable?>
    {
      TaggedObjectInfo.GetTaggedObject(
        true, 0, new DerInteger(_version - 1)),
      _serialNumber.ToPrimitive(),
      _signatureAlgorithm.ToPrimitive(),
      _issuer.ToPrimitive(),
      new List<Asn1Encodable>
      {
        new DerUtcTime(_startDate),
        new DerUtcTime(_endDate)
      }.ToDerSequence(),
      _subject.ToPrimitive(),
      new List<IEncodableInfo>
      {
        _subjectAlgorithm,
        _subjectData
      }.ToPrimitiveDerSequence(),
      _extensions != null
        ? TaggedObjectInfo.GetTaggedObject(
          true,
          3,
          _extensions.ToPrimitiveDerSequence())
        : null
    }.ToDerSequence();


  public override Asn1Encodable ToPrimitive() => ToDLSequence();
}