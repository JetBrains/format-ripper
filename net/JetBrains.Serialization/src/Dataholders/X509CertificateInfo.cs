using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace JetBrains.Serialization;

[JsonObject(MemberSerialization.Fields)]
public class X509CertificateInfo : IEncodableInfo
{
  public int Version { get; }
  public string SerialNumber { get; }
  public AlgorithmInfo SignatureAlgorithm { get; }
  public X500NameInfo Issuer { get; }
  public DateTime StartDate { get; }
  public DateTime EndDate { get; }
  public X500NameInfo Subject { get; }
  public AlgorithmInfo SubjectAlgorithm { get; }
  public TextualInfo SubjectData { get; }
  public List<ExtensionInfo>? Extensions { get; }

  public X509CertificateInfo(
    int version,
    string serialNumber,
    AlgorithmInfo signatureAlgorithm,
    X500NameInfo issuer,
    DateTime startDate,
    DateTime endDate,
    X500NameInfo subject,
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
      certificateHolder.SerialNumber.ToString(),
      new AlgorithmInfo(certificateHolder.Signature),
      new X500NameInfo(certificateHolder.Issuer),
      certificateHolder.StartDate.ToDateTime(),
      certificateHolder.EndDate.ToDateTime(),
      new X500NameInfo(certificateHolder.Subject),
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
  private DerSequence ToDLSequence()
  {
    return new DerSequence(
      new DerTaggedObject(
        true, 0, new DerInteger(Version - 1)),
      new DerInteger(new BigInteger(SerialNumber)),
      SignatureAlgorithm.ToPrimitive(),
      Issuer.ToPrimitive(),
      new DerSequence(
        new DerUtcTime(StartDate),
        new DerUtcTime(EndDate)),
      Subject.ToPrimitive(),
      new DerSequence(
        SubjectAlgorithm.ToPrimitive(),
        SubjectData.ToPrimitive()),
      Extensions != null
        ? new DerTaggedObject(
          true,
          3,
          new DerSequence(Extensions.Select(e => e.ToPrimitive()).ToArray()))
        : null
    );
  }

  public Asn1Encodable ToPrimitive() => ToDLSequence();
}