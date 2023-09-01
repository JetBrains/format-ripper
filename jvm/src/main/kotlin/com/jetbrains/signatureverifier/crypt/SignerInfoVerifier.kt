package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.Messages
import com.jetbrains.signatureverifier.NullLogger
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation
import com.jetbrains.signatureverifier.bouncycastle.tsp.TimeStampToken
import com.jetbrains.signatureverifier.crypt.BcExt.FormatId
import com.jetbrains.signatureverifier.crypt.BcExt.GetFirstAttributeValue
import com.jetbrains.signatureverifier.crypt.BcExt.ToJavaX509Certificate
import com.jetbrains.signatureverifier.crypt.BcExt.ToX509CertificateHolder
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToLocalDateTime
import com.jetbrains.signatureverifier.crypt.Utils.FlatMessages
import com.jetbrains.signatureverifier.crypt.Utils.ToString
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.util.Selector
import org.bouncycastle.util.Store
import org.jetbrains.annotations.NotNull
import java.security.cert.*
import java.util.*

open class SignerInfoVerifier {
  private val _signer: SignerInformation
  private val _certs: Store<X509CertificateHolder>
  private val _crlProvider: CrlProvider
  private val _logger: ILogger
  private val TimeStampToken by lazy { timeStampToken() }
  private val CounterSignatures by lazy { counterSignatures() }

  constructor(
    @NotNull signer: SignerInformation,
    @NotNull certs: Store<X509CertificateHolder>,
    @NotNull crlProvider: CrlProvider,
    logger: ILogger?
  ) {
    _signer = signer
    _certs = certs
    _crlProvider = crlProvider
    _logger = logger ?: NullLogger.Instance
  }

  suspend fun VerifyAsync(@NotNull signatureVerificationParams: SignatureVerificationParams): VerifySignatureResult {
    val certList = ArrayList(_certs.getMatches(_signer.sID as Selector<X509CertificateHolder>))
    if (certList.isEmpty()) {
      _logger.Error(Messages.signer_cert_not_found)
      return VerifySignatureResult(VerifySignatureStatus.InvalidSignature, Messages.signer_cert_not_found)
    }
    val cert = certList[0] as X509CertificateHolder
    try {
      val verifier = JcaSignerInfoVerifierBuilder(JcaDigestCalculatorProviderBuilder().build()).build(cert)

      if (!_signer.verify(verifier))
        return VerifySignatureResult(VerifySignatureStatus.InvalidSignature)

      if (signatureVerificationParams.BuildChain)
        applySignValidationTime(signatureVerificationParams)

      val verifyCounterSignResult = verifyCounterSignAsync(signatureVerificationParams)
      if (verifyCounterSignResult.NotValid)
        return verifyCounterSignResult

      val verifyTimeStampResult = verifyTimeStampAsync(signatureVerificationParams)
      if (verifyTimeStampResult.NotValid)
        return verifyTimeStampResult

      val verifyNestedSignsResult = verifyNestedSignsAsync(signatureVerificationParams)
      if (verifyNestedSignsResult.NotValid)
        return verifyNestedSignsResult

      if (signatureVerificationParams.BuildChain)
        return buildCertificateChainAsync(cert, _certs, signatureVerificationParams)

      return VerifySignatureResult.Valid
    } catch (ex: CMSException) {
      return VerifySignatureResult(VerifySignatureStatus.InvalidSignature, ex.FlatMessages())
    } catch (ex: CertificateExpiredException) {
      return VerifySignatureResult(VerifySignatureStatus.InvalidSignature, ex.FlatMessages())
    }
  }

  private fun applySignValidationTime(signatureVerificationParams: SignatureVerificationParams) {
    if (signatureVerificationParams.SignValidationTimeMode != SignatureValidationTimeMode.Timestamp || signatureVerificationParams.SignatureValidationTime != null)
      return

    val signValidationTime = getSigningTime() ?: getTimestamp()
    if (signValidationTime != null)
      signatureVerificationParams.SetSignValidationTime(signValidationTime.ConvertToLocalDateTime())
    else
      _logger.Warning("Unknown sign validation time")
  }

  private suspend fun verifyNestedSignsAsync(signatureVerificationParams: SignatureVerificationParams): VerifySignatureResult {
    val verifyNestedSignsResult = verifyNestedSignsAsync(OIDs.SPC_NESTED_SIGNATURE, signatureVerificationParams)
    if (verifyNestedSignsResult.NotValid)
      return verifyNestedSignsResult

    val verifyMsCounterSignsResult = verifyNestedSignsAsync(OIDs.MS_COUNTER_SIGN, signatureVerificationParams)
    if (verifyMsCounterSignsResult.NotValid)
      return verifyMsCounterSignsResult

    return VerifySignatureResult.Valid
  }

  private suspend fun verifyNestedSignsAsync(
    attrOid: ASN1ObjectIdentifier,
    signatureVerificationParams: SignatureVerificationParams
  ): VerifySignatureResult {
    val nestedSignAttrs = _signer.unsignedAttributes?.getAll(attrOid) ?: return VerifySignatureResult.Valid

    for (_nestedSignAttr in nestedSignAttrs) {
      val nestedSignAttr = _nestedSignAttr as Attribute
      for (attrValue in nestedSignAttr.attrValues) {
        val nestedSignedMessage = SignedMessage(attrValue.toASN1Primitive())
        val nestedSignVerifyResult = SignedMessageVerifier(_crlProvider, _logger).VerifySignatureAsync(
          nestedSignedMessage,
          signatureVerificationParams
        )
        if (nestedSignVerifyResult.NotValid)
          return nestedSignVerifyResult
      }
    }
    return VerifySignatureResult.Valid
  }

  private suspend fun verifyCounterSignAsync(signatureVerificationParams: SignatureVerificationParams): VerifySignatureResult {
    val signerInfoWraps = CounterSignatures.map { signerInformation ->
      SignerInfoVerifier(
        signerInformation,
        _certs,
        _crlProvider,
        _logger
      )
    }
    for (signerInfoWrap in signerInfoWraps) {
      val res = signerInfoWrap.VerifyAsync(signatureVerificationParams)
      if (res.NotValid)
        return res
    }
    return VerifySignatureResult.Valid
  }

  private suspend fun verifyTimeStampAsync(signatureVerificationParams: SignatureVerificationParams): VerifySignatureResult {
    val tst = TimeStampToken ?: return VerifySignatureResult.Valid
    val tstCerts = tst.certificates
    val tstCertsList = ArrayList(tstCerts.getMatches(tst.sID as Selector<X509CertificateHolder>))
    if (tstCertsList.count() < 1)
      return VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, Messages.signer_cert_not_found)

    val tstCert = tstCertsList[0] as X509CertificateHolder
    try {
      val verifier = JcaSignerInfoVerifierBuilder(JcaDigestCalculatorProviderBuilder().build()).build(tstCert)
      tst.validate(verifier)
      if (signatureVerificationParams.BuildChain)
        try {
          val tstCmsSignedData = tst.toCMSSignedData()
          val certs = tstCmsSignedData.certificates
          return buildCertificateChainAsync(tstCert, certs, signatureVerificationParams)
        } catch (ex: CertPathBuilderException) {
          return VerifySignatureResult.InvalidChain(ex.FlatMessages())
        }
    } catch (ex: TSPException) {
      return VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, ex.FlatMessages())
    } catch (ex: CertificateExpiredException) {
      return VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, ex.FlatMessages())
    }
    return VerifySignatureResult.Valid
  }

  private suspend fun buildCertificateChainAsync(
    primary: X509CertificateHolder,
    intermediateCertsStore: Store<X509CertificateHolder>,
    signatureVerificationParams: SignatureVerificationParams
  ): VerifySignatureResult {
    _logger.Trace("Signature validation time: ${signatureVerificationParams.SignatureValidationTime?.ToString("dd.MM.uuuu HH:mm:ss") ?: "<null>"}")

    val builderParams = CustomPkixBuilderParameters(
      signatureVerificationParams.RootCertificates!!.toHashSet(),
      intermediateCertsStore,
      X509CertSelector().also { it.certificate = primary.ToJavaX509Certificate() },
      signatureVerificationParams.SignatureValidationTime
    )

    val useOCSP = signatureVerificationParams.WithRevocationCheck &&
      builderParams.PrepareCrls(_crlProvider)

    try {
      val builder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType())
      val chain = builder.build(builderParams) as PKIXCertPathBuilderResult

      if (useOCSP) {
        _logger.Trace("Start OCSP for certificate ${primary.FormatId()}")
        val issuerCert = getIssuerCert(chain, primary)
        return OcspVerifier(signatureVerificationParams.OcspResponseTimeout, _logger)
          .CheckCertificateRevocationStatusAsync(primary, issuerCert!!)
      }

      return VerifySignatureResult.Valid
    } catch (ex: CertPathBuilderException) {
      _logger.Error("Build chain for certificate was failed. ${primary.FormatId()} ${ex.FlatMessages()}")
      return VerifySignatureResult.InvalidChain(ex.FlatMessages())
    }
  }

  private fun getIssuerCert(chain: PKIXCertPathBuilderResult, cert: X509CertificateHolder): X509CertificateHolder? {
    return chain.certPath.certificates.map { it.ToX509CertificateHolder() }
      .lastOrNull { it.subject.equals(cert.issuer) }
      ?: chain.trustAnchor.trustedCert?.ToX509CertificateHolder()
  }

  private fun counterSignatures(): Collection<SignerInformation> {
    val res = mutableListOf<SignerInformation>()

    fun addCounterSign(current: SignerInformation) {
      for (signer in current.getCounterSignatures().signers) {
        res.add(signer)
        addCounterSign(signer)
      }
    }
    addCounterSign(_signer)
    return res
  }

  private fun timeStampToken(): TimeStampToken? {
    val timestampAttrValue =
      getUnsignedAttributeValue(OIDs.MS_COUNTER_SIGN) ?: getUnsignedAttributeValue(OIDs.TIMESTAMP_TOKEN) ?: return null
    val contentInfo = ContentInfo.getInstance(timestampAttrValue)
    val cmsSignedData = CMSSignedData(contentInfo)
    return TimeStampToken(cmsSignedData)
  }

  private fun getTimestamp(): Date? = TimeStampToken?.timeStampInfo?.genTime ?: getTimeStampFromCounterSign()

  private fun getTimeStampFromCounterSign(): Date? {
    val items: List<Date?> = CounterSignatures.map { signer ->
      val signingTimeAttribute = signer.signedAttributes?.get(OIDs.SIGNING_TIME)
      if (signingTimeAttribute != null && signingTimeAttribute.attrValues.count() > 0) {
        val attrValue = signingTimeAttribute.attrValues.getObjectAt(0)
        val time = Time.getInstance(attrValue)
        return time.date
      }
      return null
    }
    return items.firstOrNull { f -> f != null }
  }

  private fun getSigningTime(): Date? {
    val signingTime = getSignedAttributeValue(CMSAttributes.signingTime)
    return if (signingTime == null) null else Time.getInstance(signingTime).date
  }

  private fun getSignedAttributeValue(oid: ASN1ObjectIdentifier): ASN1Encodable? =
    _signer.signedAttributes?.GetFirstAttributeValue(oid)

  private fun getUnsignedAttributeValue(oid: ASN1ObjectIdentifier): ASN1Encodable? =
    _signer.unsignedAttributes?.GetFirstAttributeValue(oid)

  private operator fun ASN1EncodableVector.iterator(): ASN1EncodableVectorIterator {
    return ASN1EncodableVectorIterator(this)
  }
}


