package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.cert.X509CertificateHolder
import java.security.cert.X509Certificate

class VerifySignatureResult(
  private val status: VerifySignatureStatus,
  private val message: String? = null,
  certificate: X509CertificateHolder? =null
) {
  val Status: VerifySignatureStatus
    get() = status

  val Message: String?
    get() = message

  val NotValid: Boolean
    get() = status != VerifySignatureStatus.Valid

  companion object {
    val Valid = VerifySignatureResult(VerifySignatureStatus.Valid, certificate = null)

    fun InvalidChain(message: String): VerifySignatureResult =
      VerifySignatureResult(VerifySignatureStatus.InvalidChain, message, null)
  }
}

enum class VerifySignatureStatus {
  Valid,
  InvalidSignature,
  InvalidChain,
  InvalidTimestamp
}
