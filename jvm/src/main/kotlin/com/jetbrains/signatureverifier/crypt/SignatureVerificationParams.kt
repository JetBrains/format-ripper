package com.jetbrains.signatureverifier.crypt

import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.LocalDateTime
import kotlin.time.toKotlinDuration

class SignatureVerificationParams
/** Initialize SignatureVerificationParams
 * @param signRootCertStore Stream of PKCS #7 store with CA certificates for which a chain will be build and validate
 * @param timestampRootCertStore Stream of PKCS #7 store with a timestamp CA certificates for which a chain will be build and validate
 * @param buildChain If true - build and verify a certificates chain (by default true)
 * @param withRevocationCheck If true - verify a revocation status for certificates in all chains (apply if buildChain is true, by default true)
 * @param ocspResponseTimeout Timeout for OCSP request (5 sec. by default) (apply if withRevocationCheck is true)
 * @param signatureValidationTimeMode Mode of selection time which is used for certificates and CRLs validation (SignatureValidationTimeMode.Timestamp by default)
 * @param signatureValidationTime Time which is used when signatureValidationTimeMode is SignValidationTime
 */(
  signRootCertStore: InputStream? = null,
  timestampRootCertStore: InputStream? = null,
  buildChain: Boolean = true,
  withRevocationCheck: Boolean = true,
  ocspResponseTimeout: Duration? = null,
  signatureValidationTimeMode: SignatureValidationTimeMode = SignatureValidationTimeMode.Timestamp,
  signatureValidationTime: LocalDateTime? = null,
  val expectedResult: VerifySignatureStatus = VerifySignatureStatus.Valid,
  val testedFileName: String?
) {
  val _signRootCertStore: InputStream? = signRootCertStore
  val _timestampRootCertStore: InputStream? = timestampRootCertStore

  val BuildChain: Boolean = buildChain
  val WithRevocationCheck: Boolean = withRevocationCheck
  val OcspResponseTimeout: Duration
  val SignValidationTimeMode: SignatureValidationTimeMode = signatureValidationTimeMode
  var SignatureValidationTime: LocalDateTime? = signatureValidationTime

  private val SignatureValidationTimeFormatted: String
    get() = SignatureValidationTime?.toString() ?: "<null>"

  internal val RootCertificates: HashSet<TrustAnchor>? by lazy { readRootCertificates() }

  init {
    OcspResponseTimeout = ocspResponseTimeout ?: Duration.ofSeconds(5)
    if (SignValidationTimeMode == SignatureValidationTimeMode.SignValidationTime
      && signatureValidationTime == null
    )
      error("signatureValidationTime is empty")
  }

  fun SetSignValidationTime(signValidationTime: LocalDateTime) {
    if (SignValidationTimeMode != SignatureValidationTimeMode.Timestamp)
      error("Invalid SignValidationTimeMode")

    if (SignatureValidationTime != null)
      error("SignatureValidationTime already set")

    SignatureValidationTime = signValidationTime
  }

  private fun readRootCertificates(): HashSet<TrustAnchor>? {
    if (_signRootCertStore == null
      && _timestampRootCertStore == null
    ) return null

    val rootCerts = HashSet<TrustAnchor>()
    _signRootCertStore?.let { addCerts(it, rootCerts) }
    _timestampRootCertStore?.let { addCerts(it, rootCerts) }
    return rootCerts
  }

  private fun addCerts(storeStream: InputStream, rootCerts: HashSet<TrustAnchor>) {
    val cf = CertificateFactory.getInstance("X.509")
    val certs = cf.generateCertificates(storeStream)
    rootCerts.addAll(certs.map { TrustAnchor(it as X509Certificate, null) })
  }

  override fun toString(): String {
    return "BuildChain: $BuildChain, WithRevocationCheck: $WithRevocationCheck, OcspResponseTimeout: ${OcspResponseTimeout.toKotlinDuration()}, SignValidationTimeMode: $SignValidationTimeMode, SignatureValidationTime: $SignatureValidationTime"
  }
}

enum class SignatureValidationTimeMode {
  /* Extract a timestamp or signing time (1.2.840.113549.1.9.5) from a signed message */
  Timestamp,

  /* Validate signatures in the current time */
  Current,

  /* Validate signatures in the particular time */
  SignValidationTime
}
