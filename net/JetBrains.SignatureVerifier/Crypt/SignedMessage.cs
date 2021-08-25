using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.Annotations;
using JetBrains.SignatureVerifier.Crypt.BC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using CmsSignedData = JetBrains.SignatureVerifier.Crypt.BC.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;

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

        public VerifySignatureResult VerifySignature(Stream signRootCertStore, Stream timestampRootCertStore)
        {
            return VerifySignature(readRootCertificates(signRootCertStore, timestampRootCertStore));
        }

        internal VerifySignatureResult VerifySignature(HashSet rootCertificates)
        {
            return verifySignature(_cmsSignedData, rootCertificates);
        }

        private VerifySignatureResult verifySignature(CmsSignedData cmsSignedData, HashSet rootCertificates)
        {
            var certs = cmsSignedData.GetCertificates("Collection");
            var signersStore = cmsSignedData.GetSignerInfos();
            return verifySignature(signersStore, certs, rootCertificates);
        }

        private VerifySignatureResult verifySignature(IReadOnlyCollection<SignerInformation> signersStore,
            IX509Store certs,
            HashSet rootCertificates)
        {
            foreach (var signer in signersStore)
            {
                var siw = new SignerInfoWrap(signer, certs, rootCertificates);
                var result = siw.Verify();

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