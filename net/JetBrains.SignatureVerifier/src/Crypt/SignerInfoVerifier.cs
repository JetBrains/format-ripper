using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using CmsSignedData = JetBrains.SignatureVerifier.Crypt.BC.CmsSignedData;
using SignerInformation = JetBrains.SignatureVerifier.Crypt.BC.SignerInformation;
using Time = Org.BouncyCastle.Asn1.Cms.Time;
using TimeStampToken = JetBrains.SignatureVerifier.Crypt.BC.TimeStampToken;

namespace JetBrains.SignatureVerifier.Crypt
{
  class SignerInfoVerifier
  {
    private readonly SignerInformation _signer;
    private readonly IX509Store _certs;
    private readonly CrlProvider _crlProvider;
    private readonly ILogger _logger;
    private TimeStampToken _timeStampToken;
    private List<SignerInformation> _counterSignatures;
    private TimeStampToken TimeStampToken => _timeStampToken ??= getTimeStampToken();
    private List<SignerInformation> CounterSignatures => _counterSignatures ??= getCounterSignatures();

    public SignerInfoVerifier([NotNull] SignerInformation signer,
      [NotNull] IX509Store certs,
      CrlProvider crlProvider,
      ILogger logger)
    {
      _signer = signer ?? throw new ArgumentNullException(nameof(signer));
      _certs = certs ?? throw new ArgumentNullException(nameof(certs));
      _crlProvider = crlProvider ?? throw new ArgumentNullException(nameof(crlProvider));
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

        if (signatureVerificationParams.BuildChain)
          applySignValidationTime(signatureVerificationParams);

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
      catch (CertificateExpiredException ex)
      {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature)
          { Message = ex.FlatMessages() };
      }
    }

    private void applySignValidationTime(SignatureVerificationParams signatureVerificationParams)
    {
      if (signatureVerificationParams.SignValidationTimeMode != SignatureValidationTimeMode.Timestamp ||
          signatureVerificationParams.SignatureValidationTime.HasValue)
        return;

      var signValidationTime = getSigningTime() ?? getTimestamp();

      if (signValidationTime.HasValue)
        signatureVerificationParams.SetSignValidationTime(signValidationTime.Value);
      else
        _logger.Warning("Unknown sign validation time");
    }

    private async Task<VerifySignatureResult> verifyNestedSignsAsync(
      SignatureVerificationParams signatureVerificationParams)
    {
      var verifyNestedSignsResult =
        await verifyNestedSignsAsync(OIDs.SPC_NESTED_SIGNATURE, signatureVerificationParams);

      if (verifyNestedSignsResult.NotValid)
        return verifyNestedSignsResult;

      var verifyMsCounterSignsResult = await verifyNestedSignsAsync(OIDs.MS_COUNTER_SIGN, signatureVerificationParams);

      if (verifyMsCounterSignsResult.NotValid)
        return verifyMsCounterSignsResult;

      return VerifySignatureResult.Valid;
    }

    private async Task<VerifySignatureResult> verifyNestedSignsAsync(DerObjectIdentifier attrOid,
      SignatureVerificationParams signatureVerificationParams)
    {
      var nestedSignAttrs = _signer.UnsignedAttributes?.GetAll(attrOid);

      if (nestedSignAttrs is null)
        return VerifySignatureResult.Valid;

      foreach (Attribute nestedSignAttr in nestedSignAttrs)
      {
        foreach (Asn1Encodable attrValue in nestedSignAttr.AttrValues)
        {
          var nestedSignedMessage =
            new SignedMessage(attrValue.ToAsn1Object());

          var nestedSignVerifyResult =
            await new SignedMessageVerifier(_crlProvider, _logger).VerifySignatureAsync(nestedSignedMessage,
              signatureVerificationParams);

          if (nestedSignVerifyResult.NotValid)
            return nestedSignVerifyResult;
        }
      }

      return VerifySignatureResult.Valid;
    }

    private async Task<VerifySignatureResult> verifyCounterSignAsync(
      SignatureVerificationParams signatureVerificationParams)
    {
      var signerInfoWraps = CounterSignatures.Select(signerInformation =>
        new SignerInfoVerifier(signerInformation, _certs, _crlProvider, _logger));

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
      _logger.Trace(
        $"Signature validation time: {signatureVerificationParams.SignatureValidationTime?.ToString("dd.MM.yyyy HH:mm:ss") ?? "<null>"}");

      var builderParams = new CustomPkixBuilderParameters(
        signatureVerificationParams.RootCertificates,
        intermediateCertsStore,
        new X509CertStoreSelector { Certificate = primary },
        signatureVerificationParams.SignatureValidationTime);

      var useOCSP = signatureVerificationParams.WithRevocationCheck &&
                    await builderParams.PrepareCrls(_crlProvider);

      try
      {
        var builder = new PkixCertPathBuilder();
        var chain = builder.Build(builderParams);

        if (useOCSP)
        {
          _logger.Trace($"Start OCSP for certificate {primary.FormatId()}");
          var issuerCert = getIssuerCert(chain, primary);
          return await new OcspVerifier(signatureVerificationParams.OcspResponseTimeout, _logger)
            .CheckCertificateRevocationStatusAsync(primary, issuerCert);
        }

        return VerifySignatureResult.Valid;
      }
      catch (PkixCertPathBuilderException ex)
      {
        _logger.Error($"Build chain for certificate was failed. {primary.FormatId()} {ex.FlatMessages()}");
        return VerifySignatureResult.InvalidChain(ex.FlatMessages());
      }
    }

    private X509Certificate getIssuerCert(PkixCertPathBuilderResult chain, X509Certificate cert)
    {
      return chain.CertPath.Certificates.Cast<X509Certificate>()
               .LastOrDefault(s => s.SubjectDN.Equivalent(cert.IssuerDN))
             ?? chain.TrustAnchor.TrustedCert;
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