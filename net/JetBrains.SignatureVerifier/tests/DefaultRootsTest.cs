using System.Linq;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;
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
      var trustedCerts = SignatureVerifier.ResourceUtil.OpenDefaultRoots(codeSignRootsStream =>
        {
          var verificationParams = new SignatureVerificationParams(
            codeSignRootsStream,
            withRevocationCheck: false);
          return verificationParams.RootCertificates.Cast<TrustAnchor>().Select(_ => _.TrustedCert).ToList();
        });
      trustedCerts.Sort((x, y) => string.CompareOrdinal(x.IssuerDN.ToString(), y.IssuerDN.ToString()));

      (string HexSerialNumber, string IssuerDN)[] originals =
        {
          // @formatter:off
          ("0444c0"                          , "C=PL,O=Unizeto Technologies S.A.,OU=Certum Certification Authority,CN=Certum Trusted Network CA"                                                             ),
          ("02"                              , "C=US,O=Apple Inc.,OU=Apple Certification Authority,CN=Apple Root CA"                                                                                         ),
          ("4a538c28"                        , "C=US,O=Entrust\\, Inc.,OU=See www.entrust.net/legal-terms,OU=(c) 2009 Entrust\\, Inc. - for authorized use only,CN=Entrust Root Certification Authority - G2"),
          ("00"                              , "C=US,ST=Arizona,L=Scottsdale,O=GoDaddy.com\\, Inc.,CN=Go Daddy Root Certificate Authority - G2"                                                              ),
          ("01fd6d30fca3ca51a81bbc640e35032d", "C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority"                                                           ),
          ("56b629cd34bc78f6"                , "C=US,ST=Texas,L=Houston,O=SSL Corporation,CN=SSL.com EV Root Certification Authority RSA R2"                                                                 ),
          ("28cc3a25bfba44ac449a9b586b4339aa", "C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2010"                                                           ),
          ("3f8bc8b5fc9fb29643b569d66c42e144", "C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2011"                                                           ),
          ("79ad16a14aa0a5ad4c7358f407132e65", "DC=com,DC=microsoft,CN=Microsoft Root Certificate Authority"                                                                                                 )
          // @formatter:on
        };

      Assert.AreEqual(originals.Length, trustedCerts.Count);
      for (var n = 0; n < trustedCerts.Count; ++n)
      {
        Assert.AreEqual(new BigInteger(originals[n].HexSerialNumber, 16), trustedCerts[n].SerialNumber);
        Assert.AreEqual(originals[n].IssuerDN, trustedCerts[n].IssuerDN.ToString());
      }
    }
  }
}