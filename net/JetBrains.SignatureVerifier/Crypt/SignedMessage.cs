using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using CmsSignedData = JetBrains.SignatureVerifier.BouncyCastle.Cms.CmsSignedData;
using SignerInformationStore = JetBrains.SignatureVerifier.BouncyCastle.Cms.SignerInformationStore;

namespace JetBrains.SignatureVerifier.Crypt
{
    public class SignedMessage
    {
        private readonly CmsSignedData _cmsSignedData;

        public SignedMessage([NotNull] byte[] data)
        {
            var _data = data ?? throw new ArgumentNullException(nameof(data));

            var asnStream = new Asn1InputStream(_data);
            var pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
            _cmsSignedData = new CmsSignedData(pkcs7);
        }

        internal SignedMessage([NotNull] Asn1Object obj)
        {
            if (obj == null) throw new ArgumentNullException(nameof(obj));

            var pkcs7 = ContentInfo.GetInstance(obj);
            _cmsSignedData = new CmsSignedData(pkcs7);
        }

        public Task<VerifySignatureResult> VerifySignatureAsync(
            Stream signRootCertStore,
            Stream timestampRootCertStore,
            bool withRevocationCheck)
        {
            return VerifySignatureAsync(readRootCertificates(signRootCertStore, timestampRootCertStore), withRevocationCheck);
        }

        internal Task<VerifySignatureResult> VerifySignatureAsync(HashSet rootCertificates, bool withRevocationCheck)
        {
            return verifySignatureAsync(_cmsSignedData, rootCertificates, withRevocationCheck);
        }

        private Task<VerifySignatureResult> verifySignatureAsync(
            CmsSignedData cmsSignedData, 
            HashSet rootCertificates, 
            bool withRevocationCheck)
        {
            var certs = cmsSignedData.GetCertificates("Collection");
            var signersStore = cmsSignedData.GetSignerInfos();
            return verifySignatureAsync(signersStore, certs, rootCertificates, withRevocationCheck);
        }

        private async Task<VerifySignatureResult> verifySignatureAsync(
            SignerInformationStore signersStore,
            IX509Store certs,
            HashSet rootCertificates,
            bool withRevocationCheck)
        {
            foreach (JetBrains.SignatureVerifier.BouncyCastle.Cms.SignerInformation signer in signersStore.GetSigners())
            {
                var siv = new SignerInfoVerifier(signer, certs, rootCertificates);
                var result = await siv.VerifyAsync(withRevocationCheck);

                if (result != VerifySignatureResult.OK)
                    return result;
            }

            return VerifySignatureResult.OK;
        }

        private HashSet readRootCertificates(Stream signRootCertStore, Stream timestampRootCertStore)
        {
            if (signRootCertStore is null 
                && timestampRootCertStore is null)
                return null;

            HashSet rootCerts = new HashSet();
            X509CertificateParser parser = new X509CertificateParser();
            addCerts(signRootCertStore);
            addCerts(timestampRootCertStore);
            return rootCerts;

            void addCerts(Stream storeStream)
            {
                if (storeStream is not null)
                    rootCerts.AddAll(parser.ReadCertificates(storeStream)
                            .Cast<X509Certificate>()
                            .Select(cert => new TrustAnchor(cert, new byte[0])));
            }
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