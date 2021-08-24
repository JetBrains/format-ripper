using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.SignatureVerifier.Crypt.BC;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using CmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;
using TimeStampToken = JetBrains.SignatureVerifier.Crypt.BC.TimeStampToken;

namespace JetBrains.SignatureVerifier.Crypt
{
    class SignerInfoWrap
    {
        private readonly SignerInformation _signer;
        private readonly IX509Store _certs;
        private readonly HashSet _rootCertificates;
        private TimeStampToken _timeStampToken;
        private List<SignerInformation> _counterSignatures;

        private TimeStampToken TimeStampToken => _timeStampToken ??= getTimeStampToken();

        private List<SignerInformation> CounterSignatures => _counterSignatures ??= getCounterSignatures();

        public SignerInfoWrap(SignerInformation signer, IX509Store certs, HashSet rootCertificates)
        {
            _signer = signer;
            _certs = certs;
            _rootCertificates = rootCertificates;
        }

        public VerifySignatureResult Verify(DateTime? signValidationTime = null)
        {
            var certList = new ArrayList(_certs.GetMatches(_signer.SignerID));

            if (certList.Count < 1)
                return VerifySignatureResult.InvalidSignature;

            var cert = (X509Certificate) certList[0];

            try
            {
                if (!_signer.Verify(cert))
                    return VerifySignatureResult.InvalidSignature;

                var verifySignatureResult = veriryCounterSign(getTimestamp() ?? signValidationTime);

                if (verifySignatureResult != VerifySignatureResult.OK)
                    return verifySignatureResult;

                verifySignatureResult = verifyTimeStamp();

                if (verifySignatureResult != VerifySignatureResult.OK)
                    return verifySignatureResult;

                verifySignatureResult = verifyNestedSigns();

                if (verifySignatureResult != VerifySignatureResult.OK)
                    return verifySignatureResult;

                if (_rootCertificates != null)
                    try
                    {
                        buildCertificateChain(cert, _certs, _rootCertificates, getTimestamp() ?? signValidationTime);
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

        private VerifySignatureResult verifyNestedSigns()
        {
            var nestedSignAttrs = _signer.UnsignedAttributes?.GetAll(OIDs.SPC_NESTED_SIGNATURE);

            if (nestedSignAttrs != null)
            {
                foreach (Attribute nestedSignAttr in nestedSignAttrs)
                {
                    if (nestedSignAttr.AttrValues.Count > 0)
                    {
                        var nestedSignVerifyResult =
                            new SignedMessage(nestedSignAttr.AttrValues[0].ToAsn1Object()).VerifySignature(
                                _rootCertificates);

                        if (nestedSignVerifyResult != VerifySignatureResult.OK)
                            return nestedSignVerifyResult;
                    }
                }
            }

            return VerifySignatureResult.OK;
        }

        private VerifySignatureResult veriryCounterSign(DateTime? signValidationTime)
        {
            var signerInfoWraps = CounterSignatures.Select(signerInformation =>
                new SignerInfoWrap(signerInformation, _certs, _rootCertificates));

            foreach (var signerInfoWrap in signerInfoWraps)
            {
                var res = signerInfoWrap.Verify(signValidationTime);

                if (res != VerifySignatureResult.OK)
                    return res;
            }

            return VerifySignatureResult.OK;
        }

        private VerifySignatureResult verifyTimeStamp()
        {
            var tst = TimeStampToken;

            if (tst == null)
                return VerifySignatureResult.OK;

            var tstCerts = tst.GetCertificates("Collection");
            var tstCertsList = new ArrayList(tstCerts.GetMatches(tst.SignerID));

            if (tstCertsList.Count < 1)
                return VerifySignatureResult.InvalidSignature;

            var tstCert = (X509Certificate) tstCertsList[0];

            try
            {
                tst.Validate(tstCert);

                if (_rootCertificates != null)
                    try
                    {
                        var tstCmsSignedData = tst.ToCmsSignedData();
                        var certs = tstCmsSignedData.GetCertificates("Collection");
                        buildCertificateChain(tstCert, certs, _rootCertificates, getTimestamp());
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

        void buildCertificateChain(X509Certificate primary, IX509Store additional, HashSet rootCertificates,
            DateTime? signValidationTime)
        {
            var builder = new PkixCertPathBuilder();
            var holder = new X509CertStoreSelector {Certificate = primary};

            var builderParams = new CustomPkixBuilderParameters(rootCertificates, holder)
            {
                IsRevocationEnabled = false,
                ValidityModel = PkixParameters.ChainValidityModel,
                Date = signValidationTime.HasValue ? new DateTimeObject(signValidationTime.Value) : null
            };

            builderParams.AddStore(additional);
            builder.Build(builderParams);
        }

        private List<SignerInformation> getCounterSignatures()
        {
            var res = new List<SignerInformation>();
            addCounterSign(_signer);
            return res;

            void addCounterSign(SignerInformation current)
            {
                foreach (var signer in current.GetCounterSignatures())
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

                return (DateTime?) null;
            }).FirstOrDefault(f => f.HasValue);

            return res;
        }
    }
}