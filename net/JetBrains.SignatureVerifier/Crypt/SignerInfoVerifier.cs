using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using CertStatus = Org.BouncyCastle.Asn1.Ocsp.CertStatus;
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
    private readonly ILogger _logger;
    private TimeStampToken _timeStampToken;
    private List<SignerInformation> _counterSignatures;
    private TimeStampToken TimeStampToken => _timeStampToken ??= getTimeStampToken();
    private List<SignerInformation> CounterSignatures => _counterSignatures ??= getCounterSignatures();
    private CrlProvider _crlProvider;
    private CrlProvider CrlProvider => _crlProvider ??= new CrlProvider(new CrlCacheFileSystem());

    public SignerInfoVerifier([NotNull] SignerInformation signer, [NotNull] IX509Store certs, ILogger logger)
    {
      _signer = signer ?? throw new ArgumentNullException(nameof(signer));
      _certs = certs ?? throw new ArgumentNullException(nameof(certs));
      _logger = logger ?? NullLogger.Instance;
    }

    public async Task<VerifySignatureResult> VerifyAsync(
      [NotNull] SignatureVerificationParams signatureVerificationParams)
    {
      if (signatureVerificationParams == null)
        throw new ArgumentNullException(nameof(signatureVerificationParams));

      var certList = new ArrayList(_certs.GetMatches(_signer.SignerID));

      if (certList.Count < 1)
      {
        _logger.Error(Messages.signer_cert_not_found);

        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature)
          { Message = Messages.signer_cert_not_found };
      }

      var cert = (X509Certificate)certList[0];

      try
      {
        if (!_signer.Verify(cert))
          return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature);

        var verifyCounterSignResult =
          await verifyCounterSignAsync(signatureVerificationParams);

        if (verifyCounterSignResult.NotValid)
          return verifyCounterSignResult;

        var verifyTimeStampResult = await verifyTimeStampAsync(signatureVerificationParams);

        if (verifyTimeStampResult.NotValid)
          return verifyTimeStampResult;

        var verifyNestedSignsResult = await verifyNestedSignsAsync(signatureVerificationParams);

        if (verifyNestedSignsResult.NotValid)
          return verifyNestedSignsResult;

        if (signatureVerificationParams.BuildChain)
          return await buildCertificateChainAsync(cert, _certs, signatureVerificationParams);

        return VerifySignatureResult.Valid;
      }
      catch (CmsException ex)
      {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature)
          { Message = ex.FlatMessages() };
      }
    }

    private async Task<VerifySignatureResult> verifyNestedSignsAsync(
      SignatureVerificationParams signatureVerificationParams)
    {
      var nestedSignAttrs = _signer.UnsignedAttributes?.GetAll(OIDs.SPC_NESTED_SIGNATURE);

      if (nestedSignAttrs is not null)
      {
        foreach (Attribute nestedSignAttr in nestedSignAttrs)
        {
          if (nestedSignAttr.AttrValues.Count > 0)
          {
            var nestedSignedMessage =
              new SignedMessage(nestedSignAttr.AttrValues[0].ToAsn1Object(), _logger);

            var nestedSignVerifyResult =
              await nestedSignedMessage.VerifySignatureAsync(signatureVerificationParams);

            if (nestedSignVerifyResult.NotValid)
              return nestedSignVerifyResult;
          }
        }
      }

      return VerifySignatureResult.Valid;
    }

    private async Task<VerifySignatureResult> verifyCounterSignAsync(
      SignatureVerificationParams signatureVerificationParams)
    {
      var signerInfoWraps = CounterSignatures.Select(signerInformation =>
        new SignerInfoVerifier(signerInformation, _certs, _logger));

      foreach (var signerInfoWrap in signerInfoWraps)
      {
        var res = await signerInfoWrap.VerifyAsync(signatureVerificationParams);

        if (res.NotValid)
          return res;
      }

      return VerifySignatureResult.Valid;
    }

    private async Task<VerifySignatureResult> verifyTimeStampAsync(
      SignatureVerificationParams signatureVerificationParams)
    {
      var tst = TimeStampToken;

      if (tst == null)
        return VerifySignatureResult.Valid;

      var tstCerts = tst.GetCertificates("Collection");
      var tstCertsList = new ArrayList(tstCerts.GetMatches(tst.SignerID));

      if (tstCertsList.Count < 1)
        return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp)
          { Message = Messages.signer_cert_not_found };

      var tstCert = (X509Certificate)tstCertsList[0];

      try
      {
        tst.Validate(tstCert);

        if (signatureVerificationParams.BuildChain)
          try
          {
            var tstCmsSignedData = tst.ToCmsSignedData();
            var certs = tstCmsSignedData.GetCertificates("Collection");
            return await buildCertificateChainAsync(tstCert, certs, signatureVerificationParams);
          }
          catch (PkixCertPathBuilderException ex)
          {
            return VerifySignatureResult.InvalidChain(ex.FlatMessages());
          }
      }
      catch (TspException ex)
      {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp)
          { Message = ex.FlatMessages() };
      }
      catch (CertificateExpiredException ex)
      {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp)
          { Message = ex.FlatMessages() };
      }

      return VerifySignatureResult.Valid;
    }

    private async Task<VerifySignatureResult> buildCertificateChainAsync(
      X509Certificate primary,
      IX509Store intermediateCertsStore,
      SignatureVerificationParams signatureVerificationParams)
    {
      var builderParams = new CustomPkixBuilderParameters(
        signatureVerificationParams.RootCertificates,
        intermediateCertsStore,
        new X509CertStoreSelector { Certificate = primary },
        getSignValidationTime(signatureVerificationParams));

      var useOCSP = signatureVerificationParams.WithRevocationCheck &&
                    await builderParams.PrepareCrls(CrlProvider);

      try
      {
        var builder = new PkixCertPathBuilder();
        var chain = builder.Build(builderParams);

        if (useOCSP)
        {
          _logger.Trace($"Start OCSP for certificate {primary.FormatId()}");

          var issuerCert = chain.CertPath.Certificates.Cast<X509Certificate>().Last();

          return await new OcspVerifier(signatureVerificationParams.OcspResponseTimeout, _logger)
            .CheckCertificateRevocationStatusAsync(primary, issuerCert);
        }
        else
          return VerifySignatureResult.Valid;
      }
      catch (PkixCertPathBuilderException ex)
      {
        _logger.Error($"Build chain for certificate was failed. {primary.FormatId()} {ex.FlatMessages()}");
        return VerifySignatureResult.InvalidChain(ex.FlatMessages());
      }
    }

    private DateTime? getSignValidationTime(SignatureVerificationParams signatureVerificationParams)
    {
      return signatureVerificationParams.SignValidationTimeMode switch
      {
        SignatureValidationTimeMode.Timestamp => getSigningTime() ?? getTimestamp(),
        SignatureValidationTimeMode.SignValidationTime => signatureVerificationParams.SignatureValidationTime,
        SignatureValidationTimeMode.Current => null,
        _ => throw new ArgumentOutOfRangeException(nameof(signatureVerificationParams.SignValidationTimeMode))
      };
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
      var timestampAttrValue = getUnsignedAttributeValue(OIDs.MS_COUNTER_SIGN)
                               ?? getUnsignedAttributeValue(OIDs.TIMESTAMP_TOKEN);

      if (timestampAttrValue == null) return null;
      var contentInfo = ContentInfo.GetInstance(timestampAttrValue);
      var cmsSignedData = new CmsSignedData(contentInfo);
      return new TimeStampToken(cmsSignedData);
    }

    private DateTime? getTimestamp() => TimeStampToken?.TimeStampInfo.GenTime ?? getTimeStampFromCounterSign();

    private DateTime? getTimeStampFromCounterSign()
    {
      var res = CounterSignatures.Select(signer =>
      {
        var signingTimeAttribute = signer.SignedAttributes?[OIDs.SIGNING_TIME];

        if (signingTimeAttribute is not null && signingTimeAttribute.AttrValues.Count > 0)
        {
          var attrValue = signingTimeAttribute.AttrValues[0];
          var time = Time.GetInstance(attrValue);
          return time.Date;
        }

        return (DateTime?)null;
      }).FirstOrDefault(f => f.HasValue);

      return res;
    }

    private DateTime? getSigningTime()
    {
      var signingTime = getSignedAttributeValue(CmsAttributes.SigningTime);
      return signingTime == null ? null : Time.GetInstance(signingTime).Date;
    }

    private Asn1Encodable getSignedAttributeValue(DerObjectIdentifier oid) =>
      _signer.SignedAttributes?.GetFirstAttributeValue(oid);

    private Asn1Encodable getUnsignedAttributeValue(DerObjectIdentifier oid) =>
      _signer.UnsignedAttributes?.GetFirstAttributeValue(oid);
  }
}