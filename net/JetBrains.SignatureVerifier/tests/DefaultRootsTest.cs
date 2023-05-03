using System.Linq;
using JetBrains.SignatureVerifier.Crypt;
using NUnit.Framework;
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

      (string SerialNumber, string IssuerDN)[] originals =
        {
          // @formatter:off
          ("279744"                                 ,"C=PL,O=Unizeto Technologies S.A.,OU=Certum Certification Authority,CN=Certum Trusted Network CA"                                                             ),
          ("2"                                      ,"C=US,O=Apple Inc.,OU=Apple Certification Authority,CN=Apple Root CA"                                                                                         ),
          ("1246989352"                             ,"C=US,O=Entrust\\, Inc.,OU=See www.entrust.net/legal-terms,OU=(c) 2009 Entrust\\, Inc. - for authorized use only,CN=Entrust Root Certification Authority - G2"),
          ("0"                                      ,"C=US,ST=Arizona,L=Scottsdale,O=GoDaddy.com\\, Inc.,CN=Go Daddy Root Certificate Authority - G2"                                                              ),
          ("2645093764781058787591871645665788717"  ,"C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority"                                                           ),
          ("54229527761073585954067062875972909482" ,"C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2010"                                                           ),
          ("84467163898187471482657645020825444676" ,"C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Root Certificate Authority 2011"                                                           ),
          ("161735313838342892179587228130098753125","DC=com,DC=microsoft,CN=Microsoft Root Certificate Authority"                                                                                                 )
          // @formatter:on
        };

      Assert.AreEqual(originals.Length, trustedCerts.Count);
      for (var n = 0; n < trustedCerts.Count; ++n)
      {
        Assert.AreEqual(originals[n].SerialNumber, trustedCerts[n].SerialNumber.ToString());
        Assert.AreEqual(originals[n].IssuerDN, trustedCerts[n].IssuerDN.ToString());
      }
    }
  }
}