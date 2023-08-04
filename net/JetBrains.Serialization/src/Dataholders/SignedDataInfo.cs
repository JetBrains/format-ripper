using Newtonsoft.Json;
using JetBrains.SignatureVerifier.Crypt.BC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using JetBrains.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using CmsSignedData = JetBrains.SignatureVerifier.Crypt.BC.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;

[JsonObject(MemberSerialization.Fields)]
public class SignedDataInfo : IEncodableInfo
{
  public TextualInfo Version { get; }

  public List<AlgorithmInfo> DigestAlgorithmsInfo { get; }

  public EncapContentInfo EncapContentInfo { get; }

  public List<CertificateInfo> Certificates { get; }

  public List<IEncodableInfo>? CRLs { get; }

  public List<SignerInfo> SignerInfos { get; }

  public SignedDataInfo(CmsSignedData signedData)
  {
    Version = TextualInfo.GetInstance(signedData.SignedData.Version);
    DigestAlgorithmsInfo = signedData.DigestAlgorithmIdentifiers().Select(id => new AlgorithmInfo(id)).ToList();
    EncapContentInfo = EncapContentInfo.GetInstance(signedData.SignedData.EncapContentInfo);
    Certificates = signedData.GetCertificates("Collection").GetMatches(null)
      .OfType<X509Certificate>().Select(holder => CertificateInfo.GetInstance(holder.CertificateStructure)).ToList();
    CRLs = signedData.SignedData.CRLs?.OfType<Asn1Encodable>().Select(crl => crl?.ToAsn1Object().ToEncodableInfo())
      .ToList();
    SignerInfos = signedData.GetSignerInfos().GetSigners().OfType<SignerInformation>()
      .Select(info => new SignerInfo(info))
      .ToList();
  }

  public Asn1Encodable ToPrimitive()
  {
    return new List<Asn1Encodable>
    {
      Version.ToPrimitive(),
      DigestAlgorithmsInfo.ToPrimitiveDerSet(),
      EncapContentInfo.ToPrimitive(),
      TaggedObjectInfo.GetTaggedObject(false, 0, Certificates.ToPrimitiveDerSet()),
      CRLs?.ToPrimitiveDerSequence(),
      SignerInfos.ToPrimitiveDerSet()
    }.ToDerSequence();
  }

  public byte[] ToSignature(string encoding = "DER")
  {
    var signedData = SignedData.GetInstance(ToPrimitive());
    return signedData.ToContentInfo().GetEncoded(encoding);
  }
}