using System;
using System.Collections;
using System.IO;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace JetBrains.SignatureVerifier
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
                var certList = new ArrayList(certs.GetMatches(signer.SignerID));

                if (certList.Count < 1)
                    return VerifySignatureResult.InvalidSignature;

                var cert = (X509Certificate) certList[0];

                try
                {
                    if (!signer.Verify(cert))
                        return VerifySignatureResult.InvalidSignature;

                    if (rootCertificates != null)
                        try
                        {
                            BuildCertificateChain(cert, certs, rootCertificates);
                        }
                        catch (PkixCertPathBuilderException e)
                        {
                            Console.WriteLine(e);
                            return VerifySignatureResult.InvalidChain;
                        }

                    var counterSignaturesStore = signer.GetCounterSignatures();

                    if (counterSignaturesStore.Count > 0)
                        return verifySignature(counterSignaturesStore, certs, rootCertificates);

                    var attr = signer.UnsignedAttributes?[OIDs.MS_COUNTER_SIGN_OBJ_ID];

                    if (attr != null && attr.AttrValues.Count > 0)
                    {
                        var contentInfo = ContentInfo.GetInstance(attr.AttrValues[0]);
                        var cmsSignedData = new CmsSignedData(contentInfo);
                        return verifySignature(cmsSignedData, rootCertificates);
                    }
                }
                catch (CmsException e)
                {
                    Console.WriteLine(e);
                    return VerifySignatureResult.InvalidSignature;
                }
            }

            return VerifySignatureResult.OK;
        }

        static void BuildCertificateChain(X509Certificate primary, IX509Store additional, HashSet rootCertificates)
        {
            PkixCertPathBuilder builder = new PkixCertPathBuilder();

            var holder = new X509CertStoreSelector {Certificate = primary};

            var builderParams = new PkixBuilderParameters(rootCertificates, holder)
            {
                IsRevocationEnabled = false,
                ValidityModel = PkixParameters.ChainValidityModel,
                Date = new DateTimeObject(DateTime.Now.AddYears(0)) //TODO temp
            };

            builderParams.AddStore(additional);
            builder.Build(builderParams);
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