using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using CmsSignedData = JetBrains.SignatureVerifier.BouncyCastle.Cms.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.BouncyCastle.Cms.SignerInformation;
using Time = Org.BouncyCastle.Asn1.Cms.Time;
using TimeStampToken = JetBrains.SignatureVerifier.BouncyCastle.Tsp.TimeStampToken;

namespace JetBrains.SignatureVerifier.Crypt
{
    class SignerInfoVerifier
    {
        private readonly SignerInformation _signer;
        private readonly IX509Store _certs;
        private readonly HashSet _rootCertificates;
        private TimeStampToken _timeStampToken;
        private List<SignerInformation> _counterSignatures;

        private TimeStampToken TimeStampToken => _timeStampToken ??= getTimeStampToken();

        private List<SignerInformation> CounterSignatures => _counterSignatures ??= getCounterSignatures();

        public SignerInfoVerifier(SignerInformation signer, IX509Store certs, HashSet rootCertificates)
        {
            _signer = signer;
            _certs = certs;
            _rootCertificates = rootCertificates;
        }

        public async Task<VerifySignatureResult> VerifyAsync(bool withRevocationCheck,
            DateTime? signValidationTime = null)
        {
            var certList = new ArrayList(_certs.GetMatches(_signer.SignerID));

            if (certList.Count < 1)
                return VerifySignatureResult.InvalidSignature;

            var cert = (X509Certificate)certList[0];

            try
            {
                if (!_signer.Verify(cert))
                    return VerifySignatureResult.InvalidSignature;

                var verifyCounterSignResult =
                    await verifyCounterSignAsync(withRevocationCheck, getTimestamp() ?? signValidationTime);

                if (verifyCounterSignResult != VerifySignatureResult.OK)
                    return verifyCounterSignResult;

                var verifyTimeStampResult = await verifyTimeStampAsync(withRevocationCheck);

                if (verifyTimeStampResult != VerifySignatureResult.OK)
                    return verifyTimeStampResult;

                var verifyNestedSignsResult = await verifyNestedSignsAsync(withRevocationCheck);

                if (verifyNestedSignsResult != VerifySignatureResult.OK)
                    return verifyNestedSignsResult;

                if (_rootCertificates != null)
                    try
                    {
                        await buildCertificateChainAsync(cert, _certs, _rootCertificates, withRevocationCheck,
                            getTimestamp() ?? signValidationTime);
                    }
                    catch (PkixCertPathBuilderException e)
                    {
                        Console.WriteLine(e);
                        return VerifySignatureResult.InvalidChain;
                    }

                return VerifySignatureResult.OK;
            }
            catch (CmsException e)
            {
                Console.WriteLine(e);
                return VerifySignatureResult.InvalidSignature;
            }
        }

        private async Task<VerifySignatureResult> verifyNestedSignsAsync(bool withRevocationCheck)
        {
            var nestedSignAttrs = _signer.UnsignedAttributes?.GetAll(OIDs.SPC_NESTED_SIGNATURE);

            if (nestedSignAttrs != null)
            {
                foreach (Attribute nestedSignAttr in nestedSignAttrs)
                {
                    if (nestedSignAttr.AttrValues.Count > 0)
                    {
                        var nestedSignedMessage = new SignedMessage(nestedSignAttr.AttrValues[0].ToAsn1Object());
                        var nestedSignVerifyResult =
                            await nestedSignedMessage.VerifySignatureAsync(_rootCertificates, withRevocationCheck);

                        if (nestedSignVerifyResult != VerifySignatureResult.OK)
                            return nestedSignVerifyResult;
                    }
                }
            }

            return VerifySignatureResult.OK;
        }

        private async Task<VerifySignatureResult> verifyCounterSignAsync(bool withRevocationCheck,
            DateTime? signValidationTime)
        {
            var signerInfoWraps = CounterSignatures.Select(signerInformation =>
                new SignerInfoVerifier(signerInformation, _certs, _rootCertificates));

            foreach (var signerInfoWrap in signerInfoWraps)
            {
                var res = await signerInfoWrap.VerifyAsync(withRevocationCheck, signValidationTime);

                if (res != VerifySignatureResult.OK)
                    return res;
            }

            return VerifySignatureResult.OK;
        }

        private async Task<VerifySignatureResult> verifyTimeStampAsync(bool withRevocationCheck)
        {
            var tst = TimeStampToken;

            if (tst == null)
                return VerifySignatureResult.OK;

            var tstCerts = tst.GetCertificates("Collection");
            var tstCertsList = new ArrayList(tstCerts.GetMatches(tst.SignerID));

            if (tstCertsList.Count < 1)
                return VerifySignatureResult.InvalidSignature;

            var tstCert = (X509Certificate)tstCertsList[0];

            try
            {
                tst.Validate(tstCert);

                if (_rootCertificates != null)
                    try
                    {
                        var tstCmsSignedData = tst.ToCmsSignedData();
                        var certs = tstCmsSignedData.GetCertificates("Collection");
                        await buildCertificateChainAsync(tstCert, certs, _rootCertificates, withRevocationCheck,
                            getTimestamp());
                    }
                    catch (PkixCertPathBuilderException e)
                    {
                        Console.WriteLine(e);
                        return VerifySignatureResult.InvalidChain;
                    }
            }
            catch (TspException e)
            {
                Console.WriteLine(e);
                return VerifySignatureResult.InvalidTimestamp;
            }
            catch (CertificateExpiredException e)
            {
                Console.WriteLine(e);
                return VerifySignatureResult.InvalidTimestamp;
            }

            return VerifySignatureResult.OK;
        }

        private async Task buildCertificateChainAsync(
            X509Certificate primary,
            IX509Store certStore,
            HashSet rootCertificates,
            bool withRevocationCheck,
            DateTime? signValidationTime)
        {
            var builder = new PkixCertPathBuilder();
            var holder = new X509CertStoreSelector { Certificate = primary };

            var builderParams = new CustomPkixBuilderParameters(rootCertificates, holder)
            {
                IsRevocationEnabled = withRevocationCheck,
                ValidityModel = PkixParameters.ChainValidityModel,
                Date = signValidationTime.HasValue ? new DateTimeObject(signValidationTime.Value) : null
            };

            builderParams.AddStore(certStore);

            if (withRevocationCheck)
            {
                IX509Store crlStore = await getCrlStoreAsync(certStore);
                builderParams.AddStore(crlStore);
            }

            builder.Build(builderParams);
        }

        private async Task<IX509Store> getCrlStoreAsync(IX509Store certs)
        {
            var crlList = new List<X509Crl>();

            foreach (X509Certificate cert in certs.GetMatches(null))
            {
                var crls = await getCrlsAsync(cert);
                crlList.AddRange(crls);
            }

            IX509Store crlStore = X509StoreFactory.Create(
                "CRL/Collection",
                new X509CollectionStoreParameters(crlList));

            return crlStore;
        }

        private Task<List<X509Crl>> getCrlsAsync(X509Certificate cert)
        {
            var crlProvider = new CrlProvider(new CrlCacheFileSystem());
            return crlProvider.GetCrlsAsync(cert);
        }

        private List<SignerInformation> getCounterSignatures()
        {
            var res = new List<SignerInformation>();
            addCounterSign(_signer);
            return res;

            void addCounterSign(SignerInformation current)
            {
                foreach (SignerInformation signer in current.GetCounterSignatures().GetSigners())
                {
                    res.Add(signer);
                    addCounterSign(signer);
                }
            }
        }

        private TimeStampToken getTimeStampToken()
        {
            var attr = _signer.UnsignedAttributes?[OIDs.MS_COUNTER_SIGN];

            if (attr != null && attr.AttrValues.Count > 0)
            {
                var contentInfo = ContentInfo.GetInstance(attr.AttrValues[0]);
                var cmsSignedData = new CmsSignedData(contentInfo);
                return new TimeStampToken(cmsSignedData);
            }

            return null;
        }

        private DateTime? getTimestamp() => TimeStampToken?.TimeStampInfo.GenTime ?? getTimeStampFromCounterSign();

        private DateTime? getTimeStampFromCounterSign()
        {
            var res = CounterSignatures.Select(signer =>
            {
                var signingTimeAttribute = signer.SignedAttributes?[OIDs.SIGNING_TIME];

                if (signingTimeAttribute != null && signingTimeAttribute.AttrValues.Count > 0)
                {
                    var attrValue = signingTimeAttribute.AttrValues[0];
                    var time = Time.GetInstance(attrValue);
                    return time.Date;
                }

                return (DateTime?)null;
            }).FirstOrDefault(f => f.HasValue);

            return res;
        }
    }
}