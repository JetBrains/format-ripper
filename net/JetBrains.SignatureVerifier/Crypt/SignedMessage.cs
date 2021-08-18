using System;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier.Crypt
{
    public class SignedMessage
    {
        private readonly ContentInfo _pkcs7;
        private readonly SpcIndirectDataContent _indirectDataContent;

        public byte[] GetHash() => _indirectDataContent.MessageDigest.GetDigest();

        public string GetHashAlgorithmName() =>
            Org.BouncyCastle.Security.DigestUtilities.GetAlgorithmName(_indirectDataContent.MessageDigest.AlgorithmID
                .Algorithm);

        public SignedMessage([NotNull] byte[] data)
        {
            var _data = data ?? throw new ArgumentNullException(nameof(data));

            var asnStream = new Asn1InputStream(_data);
            _pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
            var signedData = SignedData.GetInstance(_pkcs7.Content);
            _indirectDataContent = new SpcIndirectDataContent(signedData.EncapContentInfo);
        }

        public VerifySignatureResult VerifySignature(byte[][] rootCertificates)
        {
            var cmsSignedData =
                new CmsSignedData(new CmsProcessableByteArray(_indirectDataContent.SignedContent), _pkcs7);
            return verifySignature(cmsSignedData, readRootCertificates(rootCertificates));
        }

        private HashSet readRootCertificates(byte[][] rootCertificates)
        {
            if (rootCertificates == null)
                return null;

            HashSet rootCerts = new HashSet();
            X509CertificateParser parser = new X509CertificateParser();

            foreach (var stream in rootCertificates)
            {
                X509Certificate rootCertificate = parser.ReadCertificate(stream);
                rootCerts.Add(new TrustAnchor(rootCertificate, new byte[0]));
            }

            return rootCerts;
        }

        private VerifySignatureResult verifySignature(CmsSignedData cmsSignedData, HashSet rootCertificates)
        {
            var certs = cmsSignedData.GetCertificates("Collection");
            var signersStore = cmsSignedData.GetSignerInfos();
            return verifySignature(signersStore, certs, rootCertificates);
        }

        private VerifySignatureResult verifySignature(SignerInformationStore signersStore, IX509Store certs,
            HashSet rootCertificates)
        {
            foreach (SignerInformation signer in signersStore.GetSigners())
            {
                var siw = new SignerInfoWrap(signer, certs, rootCertificates);
                var result = siw.Verify();

                if (result != VerifySignatureResult.OK)
                    return result;
            }

            return VerifySignatureResult.OK;
        }
    }

    public enum VerifySignatureResult
    {
        OK,
        NotSigned,
        InvalidSignature,
        InvalidChain,
        InvalidTimestamp
    }
}