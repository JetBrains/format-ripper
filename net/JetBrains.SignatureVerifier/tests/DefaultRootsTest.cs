using System.Linq;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;

namespace JetBrains.SignatureVerifier.Tests
{
  [TestFixture]
  public sealed class DefaultRootsTest
  {
    [Test]
    public void Test()
    {
      (string Name, BigInteger SerialNumber)[] expectedCertificates =
        {
          // @formatter:off
          ("Apple Root CA"                            , new BigInteger("02"                              , 16)),
          ("Certum Trusted Network CA"                , new BigInteger("0444c0"                          , 16)),
          ("Entrust Root Certification Authority - G2", new BigInteger("4a538c28"                        , 16)),
          ("Go Daddy Root Certificate Authority - G2" , new BigInteger("00"                              , 16)),
          ("Microsoft Root Certificate Authority"     , new BigInteger("79ad16a14aa0a5ad4c7358f407132e65", 16)),
          ("Microsoft Root Certificate Authority 2010", new BigInteger("28cc3a25bfba44ac449a9b586b4339aa", 16)),
          ("Microsoft Root Certificate Authority 2011", new BigInteger("3f8bc8b5fc9fb29643b569d66c42e144", 16)),
          ("USERTrust RSA Certification Authority"    , new BigInteger("01fd6d30fca3ca51a81bbc640e35032d", 16))
          // @formatter:on
        };

      (string Name, BigInteger SerialNumber)[] certificates = SignatureVerifier.ResourceUtil.OpenDefaultRoots(codeSignRootsStream =>
        {
          var verificationParams = new SignatureVerificationParams(
            codeSignRootsStream,
            withRevocationCheck: false);
          return verificationParams.RootCertificates.Cast<TrustAnchor>().Select(x => x.TrustedCert).ToList();
        }).Select(x =>
        {
          var name = x.IssuerDN.GetValueList(X509Name.CN).Cast<string>().Single();
          return (name, x.SerialNumber);
        }).OrderBy(x => x.Item1).ToArray();

      Assert.AreEqual(expectedCertificates.Length, certificates.Length);
      for (var n = 0; n < certificates.Length; ++n)
      {
        Assert.AreEqual(expectedCertificates[n].Name, certificates[n].Name);
        Assert.AreEqual(expectedCertificates[n].SerialNumber, certificates[n].SerialNumber);
      }
    }
  }
}