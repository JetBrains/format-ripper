using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.FormatRipper.Pe;
using JetBrains.SignatureVerifier.Crypt;
using Moq;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace JetBrains.SignatureVerifier.Tests
{
  public class FakePkiTest
  {
    [TestCase("ServiceModelRegUI_no_sign.dll")]
    [Test]
    public async Task InvalidSignatureNoSignerCert(string peResourceName)
    {
      var pki = FakePki.CreateRoot("fakeroot", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(10));

      (AsymmetricCipherKeyPair keyPair, X509Certificate cert) =
        pki.Enroll("sub", DateTime.UtcNow, DateTime.UtcNow.AddDays(9), false);

      using var peStream = getPeStream(peResourceName);
      using var signedPeStream = signPe(peStream, keyPair.Private, cert, false);
      var peFile = PeFile.Parse(signedPeStream, PeFile.Mode.SignatureData);
      var signedMessage = SignedMessage.CreateInstance(peFile.SignatureData);
      using var signRootCertStore = getRootStoreStream(pki.Certificate);
      var verificationParams = new SignatureVerificationParams(signRootCertStore, withRevocationCheck: false);
      var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
      var res = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      Assert.AreEqual(VerifySignatureStatus.InvalidSignature, res.Status);
    }

    [TestCase("ServiceModelRegUI_no_sign.dll")]
    [Test]
    public async Task InvalidChainCertRevoked(string peResourceName)
    {
      var pki = FakePki.CreateRoot("fakeroot", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(10));

      (AsymmetricCipherKeyPair keyPair, X509Certificate cert) =
        pki.Enroll("sub", DateTime.UtcNow, DateTime.UtcNow.AddDays(9), true);

      using var peStream = getPeStream(peResourceName);
      using var signedPeStream = signPe(peStream, keyPair.Private, cert);

      pki.Revoke(cert, true);

      var peFile = PeFile.Parse(signedPeStream, PeFile.Mode.SignatureData);
      var signedMessage = SignedMessage.CreateInstance(peFile.SignatureData);
      using var signRootCertStore = getRootStoreStream(pki.Certificate);
      var verificationParams = new SignatureVerificationParams(signRootCertStore);

      var crlSourceStub = new Mock<CrlSource>();
      crlSourceStub.Setup(m => m.GetCrlAsync(It.IsAny<string>())).ReturnsAsync(pki.Crl.GetEncoded());

      var crlCacheStub = new Mock<CrlCacheFileSystem>();
      crlCacheStub.Setup(m => m.UpdateCrls(It.IsAny<string>(), It.IsAny<List<byte[]>>()));

      var signedMessageVerifier = new SignedMessageVerifier(
        new CrlProvider(crlSourceStub.Object, crlCacheStub.Object, ConsoleLogger.Instance), ConsoleLogger.Instance);

      var res = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      Assert.AreEqual(VerifySignatureStatus.InvalidChain, res.Status);
    }

    [TestCase("ServiceModelRegUI_no_sign.dll")]
    [Test]
    public async Task InvalidChainCertOutdated(string peResourceName)
    {
      var now = DateTime.UtcNow;

      var pki = FakePki.CreateRoot("fakeroot", now.AddDays(-1), now.AddDays(10));

      (AsymmetricCipherKeyPair keyPair, X509Certificate cert) =
        pki.Enroll("sub", now, now.AddSeconds(1), false);

      await Task.Delay(2000);

      using var peStream = getPeStream(peResourceName);
      using var signedPeStream = signPe(peStream, keyPair.Private, cert);
      var peFile = PeFile.Parse(signedPeStream, PeFile.Mode.SignatureData);
      var signedMessage = SignedMessage.CreateInstance(peFile.SignatureData);
      var verificationParams = new SignatureVerificationParams(buildChain: false);
      var signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);

      var res = await signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);

      Assert.AreEqual(VerifySignatureStatus.InvalidSignature, res.Status);
    }

    private Stream signPe(Stream peStream, AsymmetricKeyParameter keyPairPrivate, X509Certificate cert,
      bool addSignerCert = true)
    {
      var cmsGen = new CmsSignedDataGenerator();
      cmsGen.AddSigner(keyPairPrivate, cert, OiwObjectIdentifiers.IdSha1.Id);

      if (addSignerCert)
        cmsGen.AddCertificates(getStore(StoreType.CERTIFICATE, cert));

      var peFile = PeFile.Parse(peStream, PeFile.Mode.ComputeHashInfo);
      var hash = HashUtil.ComputeHash(peStream, peFile.ComputeHashInfo, HashAlgorithmName.SHA1);
      var content = createCmsSignedData(hash);
      var contentData = content.GetDerEncoded();
      CmsSignedData cmsSignedData =
        cmsGen.Generate("1.3.6.1.4.1.311.2.1.4", new CmsProcessableByteArray(contentData), true);

      var signedPeStream = new MemoryStream();
      peStream.Seek(0, SeekOrigin.Begin);
      peStream.CopyTo(signedPeStream);

      using var writer = new BinaryWriter(signedPeStream, Encoding.UTF8, true);
      var encodedCmsSignedData = cmsSignedData.GetEncoded();
      signedPeStream.Seek(0, SeekOrigin.End);
      var attributeCertificateTableOffset = signedPeStream.Position;

      //write attribute certificate table
      writer.Write(encodedCmsSignedData.Length + 8); //dwLength = size + sizeof(WIN_CERTIFICATE)
      writer.Write((short) 0x0200); // wRevision = WIN_CERT_REVISION_2_0
      writer.Write((short) 2); //wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
      writer.Write(encodedCmsSignedData); //bCertificate

      //write new ImageDirectoryEntrySecurity
      signedPeStream.Seek(peFile.SecurityDataDirectoryRange.Position, SeekOrigin.Begin);
      writer.Write((int) attributeCertificateTableOffset);
      writer.Write(encodedCmsSignedData.Length);
      return signedPeStream;
    }

    private Asn1Encodable createCmsSignedData(byte[] hash)
    {
      var digestInfo = new DigestInfo(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance), hash);
      var data = new SpcAttributeOptional(new DerObjectIdentifier("1.3.6.1.4.1.311.2.1.15"),
        new SpcPeImageData());
      return new SpcIndirectDataContent(data, digestInfo);
    }

    private static Stream getRootStoreStream(X509Certificate cert)
    {
      var cmsGen = new CmsSignedDataGenerator();
      cmsGen.AddCertificates(getStore(StoreType.CERTIFICATE, cert));
      CmsSignedData cmsSignedData = cmsGen.Generate(new CmsProcessableByteArray(new byte[] { }), false);
      var data = cmsSignedData.GetEncoded();
      return new MemoryStream(data);
    }

    private static Stream getPeStream(string peResourceName)
    {
      return ResourceUtil.OpenRead(ResourceCategory.Pe, peResourceName, stream =>
        {
          var ms = new MemoryStream();
          stream.CopyTo(ms);
          return ms;
        });
    }

    private static IX509Store getStore(StoreType storeType, params X509ExtensionBase[] items)
    {
      return X509StoreFactory.Create($"{storeType}/COLLECTION", new X509CollectionStoreParameters(items));
    }

    enum StoreType
    {
      CERTIFICATE,
      CRL
    }
  }
}