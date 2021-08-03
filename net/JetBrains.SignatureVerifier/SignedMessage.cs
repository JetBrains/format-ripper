using System;
using System.Collections;
using System.Diagnostics;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier
{
    public class SignedMessage
    {
        private readonly ContentInfo _pkcs7;
        private readonly SpcIndirectDataContent _indirectDataContent;

        public SignedMessage([NotNull] byte[] data)
        {
            var _data = data ?? throw new ArgumentNullException(nameof(data));

            var asnStream = new Asn1InputStream(_data);
            _pkcs7 = ContentInfo.GetInstance(asnStream.ReadObject());
            var signedData = SignedData.GetInstance(_pkcs7.Content);
            _indirectDataContent = new SpcIndirectDataContent(signedData.EncapContentInfo);
        }

        public byte[] GetHash() => _indirectDataContent.MessageDigest.GetDigest();

        public string GetHashAlgorithmName() =>
            Org.BouncyCastle.Security.DigestUtilities.GetAlgorithmName(_indirectDataContent.MessageDigest.AlgorithmID
                .Algorithm);

        public VerifySignatureResult VerifySignature(bool withChain)
        {
            //TODO TEMP
            if (withChain)
                throw new NotImplementedException();

            return verifySignature()
                ? VerifySignatureResult.OK
                : VerifySignatureResult.InvalidSignature;
        }

        private bool verifySignature()
        {
            var cmsSignedData =
                new CmsSignedData(new CmsProcessableByteArray(_indirectDataContent.SignedContent), _pkcs7);
            var certs = cmsSignedData.GetCertificates("Collection");
            var signersStore = cmsSignedData.GetSignerInfos();
            return verifySignature(signersStore, certs);
        }

        private bool verifySignature(SignerInformationStore signersStore, IX509Store certs)
        {
            foreach (SignerInformation signer in signersStore.GetSigners())
            {
                var certList = new ArrayList(certs.GetMatches(signer.SignerID));

                if (certList.Count < 1)
                    return false;

                var cert = (X509Certificate) certList[0];

                try
                {
                    if (!signer.Verify(cert))
                        return false;
                    
                    var counterSignaturesStore = signer.GetCounterSignatures();
                    
                    if (counterSignaturesStore.Count > 0)
                        return verifySignature(counterSignaturesStore, certs);
                }
                catch (CmsException e)
                {
                    Debug.WriteLine(e);
                    throw;
                }
            }

            return true;
        }
    }

    public enum VerifySignatureResult
    {
        OK,
        NotSigned,
        InvalidSignature,
        InvalidChain
    }
}