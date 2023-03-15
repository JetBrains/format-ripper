using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace JetBrains.SignatureVerifier.Tests
{
  class FakePki
  {
    private static readonly DerObjectIdentifier RSA_ENCRYPTION = new("1.2.840.113549.1.1.1");
    private static readonly DerObjectIdentifier SHA1_WITH_RSA_SIGNATURE = new("1.2.840.113549.1.1.5");
    private readonly AsymmetricCipherKeyPair _keyPair;
    private readonly AlgorithmIdentifier _signatureAlg = new(SHA1_WITH_RSA_SIGNATURE);
    private const int publicKeyLength = 1024;

    public X509Certificate Certificate { get; }
    public X509Crl Crl { get; private set; }
    private readonly List<X509Certificate> _certificates = new();
    public IReadOnlyCollection<X509Certificate> IssuedCertificates => _certificates.AsReadOnly();
    private Dictionary<Org.BouncyCastle.Math.BigInteger, DateTime> RevokedCertificates { get; } = new();

    public static FakePki CreateRoot([NotNull] string name, DateTime utcValidFrom, DateTime utcValidTo)
    {
      if (name == null) throw new ArgumentNullException(nameof(name));

      if (utcValidFrom >= utcValidTo)
        throw new ArgumentException($"{nameof(utcValidTo)} must be greater then {nameof(utcValidFrom)}");

      return new FakePki(name, utcValidFrom, utcValidTo);
    }

    private FakePki(string name, DateTime validFrom, DateTime validTo)
    {
      _keyPair = getNewPair();
      X509Name subject = new X509Name($"CN={name}");
      var res = enroll(subject, _keyPair, name, validFrom, validTo, 0, false, false);
      Certificate = res;
      Crl = createCrl();
    }


    public (AsymmetricCipherKeyPair keyPair, X509Certificate certificate) Enroll(string name, DateTime validFrom,
      DateTime validTo, bool codeSign)
    {
      var keyPair = getNewPair();
      var certificate = enroll(Certificate.SubjectDN, keyPair, name, validFrom, validTo, _certificates.Count + 1, true,
        codeSign);
      _certificates.Add(certificate);
      return (keyPair, certificate);
    }

    public void Revoke([NotNull] X509Certificate certificate, bool renewCrl)
    {
      if (certificate == null) throw new ArgumentNullException(nameof(certificate));

      if (isIssued(certificate))
      {
        RevokedCertificates.Add(certificate.SerialNumber, DateTime.UtcNow);

        if (renewCrl)
        {
          Crl = createCrl();
        }
      }
    }

    public void UpdateCrl()
    {
      Crl = createCrl();
    }

    private bool isIssued(X509Certificate certificate)
    {
      return certificate.IssuerDN.Equivalent(Certificate.SubjectDN);
    }

    private X509Certificate enroll(X509Name issuerDN, AsymmetricCipherKeyPair keyPair,
      string subjectName, DateTime validFrom,
      DateTime validTo,
      int sn,
      bool addCrlDp,
      bool codeSign)
    {
      var version = new DerTaggedObject(0, new DerInteger(2));
      var serialNumber = new DerInteger(sn);
      var startDate = new Time(validFrom);
      var endDate = new Time(validTo);
      var dates = new DerSequence(startDate, endDate);
      var subject = new X509Name($"CN={subjectName}");
      var alg = new AlgorithmIdentifier(RSA_ENCRYPTION);
      var rsaKeyParameters = keyPair.Public as RsaKeyParameters;
      Debug.Assert(rsaKeyParameters != null, nameof(rsaKeyParameters) + " != null");
      var keyData = new RsaPublicKeyStructure(rsaKeyParameters.Modulus, rsaKeyParameters.Exponent).GetEncoded();
      var subjectPublicKeyInfo = new SubjectPublicKeyInfo(alg, keyData);
      var vec = new Asn1EncodableVector(version, serialNumber, _signatureAlg, issuerDN, dates, subject,
        subjectPublicKeyInfo);

      var extOids = new List<DerObjectIdentifier>();
      var extValues = new List<X509Extension>();

      if (addCrlDp)
      {
        var names = new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier,
          new DerIA5String("http://fakepki/crl")));

        var crlDistPoint = new CrlDistPoint(
          new[]
          {
            new DistributionPoint(new DistributionPointName(DistributionPointName.FullName, names), null, null)
          });

        extOids.Add(X509Extensions.CrlDistributionPoints);
        extValues.Add(new(false, new DerOctetString(crlDistPoint)));
      }

      if (codeSign)
      {
        extOids.Add(X509Extensions.ExtendedKeyUsage);
        extValues.Add(new(false, new DerOctetString(new DerSequence(KeyPurposeID.IdKPCodeSigning))));
      }

      Debug.Assert(extOids.Count == extValues.Count);

      if (extOids.Any())
      {
        var ext = new X509Extensions(extOids, extValues);
        vec.AddOptionalTagged(true, 3, ext);
      }

      var seq = DerSequence.FromVector(vec);
      var tbs = TbsCertificateStructure.GetInstance(seq);
      var tbsData = tbs.GetEncoded();
      var sig = sign(tbsData, _keyPair.Private);
      var cs = new X509CertificateStructure(tbs, _signatureAlg, new DerBitString(sig));

      return new X509Certificate(cs);
    }

    private X509Crl createCrl()
    {
      var version = new DerInteger(1);
      var issuer = Certificate.SubjectDN;
      var now = DateTime.UtcNow.AddMinutes(1);
      var thisUpdate = new Time(now);
      var nextUpdate = new Time(now.AddDays(5));
      var revokedCertificates = getRevokedCertificates();
      var seq = new DerSequence(version, _signatureAlg, issuer, thisUpdate, nextUpdate, revokedCertificates);
      var tbs = TbsCertificateList.GetInstance(seq);
      var tbsData = tbs.GetEncoded();
      var sig = sign(tbsData, _keyPair.Private);
      var certList = CertificateList.GetInstance(new DerSequence(tbs, _signatureAlg, new DerBitString(sig)));
      return new X509Crl(certList);
    }

    private DerSequence getRevokedCertificates()
    {
      var vec = Asn1EncodableVector.FromEnumerable(
        RevokedCertificates.Select(s => getRevokedCertificate(s.Key, s.Value)));
      return new DerSequence(vec);
    }

    private DerSequence getRevokedCertificate(Org.BouncyCastle.Math.BigInteger serialNumber, DateTime revocationTime)
    {
      return new DerSequence(new DerInteger(serialNumber), new Time(revocationTime));
    }

    private byte[] sign(byte[] data, AsymmetricKeyParameter key)
    {
      var signer = SignerUtilities.GetSigner(_signatureAlg.Algorithm.Id);
      signer.Init(true, key);
      signer.BlockUpdate(data, 0, data.Length);
      return signer.GenerateSignature();
    }

    private static AsymmetricCipherKeyPair getNewPair()
    {
      var keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator(RSA_ENCRYPTION);
      keyPairGenerator.Init(new KeyGenerationParameters(SecureRandom.GetInstance("SHA1PRNG", true), publicKeyLength));
      var keyPair = keyPairGenerator.GenerateKeyPair();
      return keyPair;
    }
  }
}