using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.OptIn)]
public class X509CertificateInfo : XCertificateInfo
{
  [JsonProperty("Version")] public int Version { get; }

  [JsonProperty("SerialNumber")] public TextualInfo SerialNumber { get; }

  [JsonProperty("SignatureAlgorithm")] public AlgorithmInfo SignatureAlgorithm { get; }

  [JsonProperty("Issuer")] public X509NameInfo Issuer { get; }

  [JsonProperty("StartDate")] public DateTime StartDate { get; }

  [JsonProperty("EndDate")] public DateTime EndDate { get; }

  [JsonProperty("Subject")] public X509NameInfo Subject { get; }

  [JsonProperty("SubjectAlgorithm")] public AlgorithmInfo SubjectAlgorithm { get; }

  [JsonProperty("SubjectData")] public TextualInfo SubjectData { get; }

  [JsonProperty("Extensions")] public List<ExtensionInfo>? Extensions { get; }

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
    Version = version;
    SerialNumber = serialNumber;
    SignatureAlgorithm = signatureAlgorithm;
    Issuer = issuer;
    StartDate = startDate;
    EndDate = endDate;
    Subject = subject;
    SubjectAlgorithm = subjectAlgorithm;
    SubjectData = subjectData;
    Extensions = extensions;
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
    new List<Asn1Encodable>
    {
      TaggedObjectInfo.GetTaggedObject(
        true, 0, new DerInteger(Version - 1)),
      SerialNumber.ToPrimitive(),
      SignatureAlgorithm.ToPrimitive(),
      Issuer.ToPrimitive(),
      new List<Asn1Encodable>
      {
        new DerUtcTime(StartDate),
        new DerUtcTime(EndDate)
      }.ToDerSequence(),
      Subject.ToPrimitive(),
      new List<IEncodableInfo>
      {
        SubjectAlgorithm,
        SubjectData
      }.ToPrimitiveDerSequence(),
      Extensions != null
        ? TaggedObjectInfo.GetTaggedObject(
          true,
          3,
          Extensions.ToPrimitiveDerSequence())
        : null
    }.ToDerSequence();


  public override Asn1Encodable ToPrimitive() => ToDLSequence();
}