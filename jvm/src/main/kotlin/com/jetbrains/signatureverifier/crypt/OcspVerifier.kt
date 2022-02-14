package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.Messages
import com.jetbrains.signatureverifier.NullLogger
import com.jetbrains.signatureverifier.crypt.BcExt.CanSignOcspResponses
import com.jetbrains.signatureverifier.crypt.BcExt.FormatId
import com.jetbrains.signatureverifier.crypt.BcExt.GetOcspUrl
import com.jetbrains.signatureverifier.crypt.BcExt.GetSubjectKeyIdentifierRaw
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToDate
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToLocalDateTime
import kotlinx.coroutines.future.await
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.jetbrains.annotations.NotNull
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime

open class OcspVerifier {
  companion object {
    private val OCSP_REQUEST_TYPE = "application/ocsp-request"
    private val OCSP_RESPONSE_TYPE = "application/ocsp-response"

    private fun formatRevokedStatus(revokedStatus: RevokedStatus): String {
      var reason = "CrlReason: <none>"
      if (revokedStatus.hasRevocationReason()) {
        val crlReason = CRLReason.getInstance(ASN1Enumerated(revokedStatus.revocationReason))
        reason = crlReason.toString()
      }
      return String.format(Messages.certificate_revoked, revokedStatus.revocationTime, reason)
    }
  }

  private var _ocspResponseTimeout: Duration = Duration.ZERO
  private val _logger: ILogger
  private val ocspResponseCorrectSpan = Duration.ofMinutes(1)

  constructor(ocspResponseTimeout: Duration, logger: ILogger) {
    _ocspResponseTimeout = ocspResponseTimeout
    _logger = logger
  }

  suspend fun CheckCertificateRevocationStatusAsync(
    @NotNull targetCert: X509CertificateHolder,
    @NotNull issuerCert: X509CertificateHolder
  ): VerifySignatureResult {
    val ocspUrl = targetCert.GetOcspUrl()
    if (ocspUrl == null) {
      _logger.Warning("The OCSP access data is empty in certificate ${targetCert.FormatId()}")
      _logger.Error(Messages.unable_determin_certificate_revocation_status)
      return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status)
    }

    val ocspReqGenerator = OCSPReqBuilder()
    val digestCalculatorProvider = org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()
    val digestCalculator = digestCalculatorProvider.get(AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
    val certificateIdReq = CertificateID(digestCalculator, issuerCert, targetCert.serialNumber)
    ocspReqGenerator.addRequest(certificateIdReq)
    val ocspReq = ocspReqGenerator.build()
    val ocspRes = getOcspResponceAsync(ocspUrl, ocspReq, _ocspResponseTimeout)

    if (ocspRes == null || ocspRes.status != OCSPResp.SUCCESSFUL) {
      _logger.Error("OCSP response status: ${ocspRes?.status}")
      return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status)
    }
    val basicOcspResp = ocspRes.responseObject as BasicOCSPResp
    if (basicOcspResp == null) {
      _logger.Error("Unknown OCSP response type")
      return VerifySignatureResult.InvalidChain(Messages.unable_determin_certificate_revocation_status)
    }
    if (!validateOcspResponse(basicOcspResp))
      return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response)

    val singleResponses = basicOcspResp.responses.filter { w -> w.certID.equals(certificateIdReq) }.toList()
    if (singleResponses.count() < 1) {
      _logger.Error("OCSP response not correspond to request")
      return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response)
    }
    for (singleResp in singleResponses) {
      if (!validateSingleOcspResponse(singleResp))
        return VerifySignatureResult.InvalidChain(Messages.invalid_ocsp_response)

      val certStatus = singleResp.certStatus
      //null is good
      if (certStatus == null) {
        continue
      } else if (certStatus is UnknownStatus) {
        _logger.Warning(Messages.unknown_certificate_revocation_status)
        return VerifySignatureResult.InvalidChain(Messages.unknown_certificate_revocation_status)
      } else if (certStatus is RevokedStatus) {
        val certRevStatus = certStatus
        val msg = formatRevokedStatus(certRevStatus)
        _logger.Warning(msg)
        return VerifySignatureResult.InvalidChain(msg)
      }
    }
    return VerifySignatureResult.Valid
  }

  private suspend fun getOcspResponceAsync(
    ocspResponderUrl: String,
    ocspRequest: OCSPReq,
    timeout: Duration
  ): OCSPResp? {
    if (!ocspResponderUrl.startsWith("http")) {
      _logger.Error("Only http(s) is supported for OCSP calls")
      return null
    }
    _logger.Trace("OCSP request: $ocspResponderUrl")
    try {
      val array = ocspRequest.encoded

      val httpClient = HttpClient.newBuilder()
        .connectTimeout(timeout)
        .build()

      val request = HttpRequest.newBuilder()
        .header("Content-Type", OCSP_REQUEST_TYPE)
        .header("Accept", OCSP_RESPONSE_TYPE)
        .uri(URI(ocspResponderUrl)).POST(HttpRequest.BodyPublishers.ofByteArray(array)).build()

      val responseData = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray()).await().body()
      return OCSPResp(responseData)
    } catch (ex: Exception) {
      val msg = "Cannot get OCSP response for url: $ocspResponderUrl"
      _logger.Error(msg)
      throw Exception(msg, ex)
    }
  }

  /**
   * Validate OCSP response with Acceptance Requirements RFC 6960 3.2
   */
  private fun validateOcspResponse(ocspResp: BasicOCSPResp): Boolean {
    val issuerCert = getOcspIssuerCert(ocspResp)
    if (issuerCert == null) {
      _logger.Error("OCSP issuer certificate not found in response")
      return false
    }
    if (!issuerCert.CanSignOcspResponses()) {
      _logger.Error("OCSP issuer certificate is not applicable. RFC 6960 3.2")
      return false
    }
    if (!issuerCert.isValidOn(nowUtc().ConvertToDate())) {
      _logger.Error("OCSP issuer certificate is not valid now. RFC 6960 3.2")
      return false
    }

    val contentVerifierProvider = JcaContentVerifierProviderBuilder().build(issuerCert)

    if (!ocspResp.isSignatureValid(contentVerifierProvider)) {
      _logger.Error("OCSP with invalid signature! RFC 6960 3.2")
      return false
    }
    return true
  }

  /**
   * Validate OCSP response with Acceptance Requirements RFC 6960 4.2.2
   */
  private fun validateSingleOcspResponse(singleResp: SingleResp): Boolean {
    val nowInGmt = nowUtc()

    if (singleResp.nextUpdate != null && singleResp.nextUpdate.before(nowInGmt.ConvertToDate())) {
      _logger.Error("OCSP response is no longer valid. NextUpdate: {singleResp.NextUpdate.Value}. RFC 6960 4.2.2.1.")
      return false
    }

    if (Duration.between(singleResp.thisUpdate.ConvertToLocalDateTime(), nowInGmt).abs() > ocspResponseCorrectSpan) {
      _logger.Error("OCSP response signature is from the future. Timestamp of thisUpdate field: ${singleResp.thisUpdate}. RFC 6960 4.2.2.1.")
      return false
    }
    return true
  }

  private fun nowUtc() = LocalDateTime.now(Clock.systemUTC())

  private fun getOcspIssuerCert(ocspResp: BasicOCSPResp): X509CertificateHolder? {
    val certs = ocspResp.certs
    if (certs == null || certs.count() < 1)
      return null

    val responderId = ocspResp.responderId.toASN1Primitive()
    if (responderId.name != null) {
      return certs.firstOrNull { f -> f.subject.equals(responderId.name) }
    } else {
      val keyHash = responderId.keyHash ?: return null

      return certs.firstOrNull { f ->
        val ki = f.GetSubjectKeyIdentifierRaw()
        ki != null && keyHash.contentEquals(ki)
      }
    }
  }
}
