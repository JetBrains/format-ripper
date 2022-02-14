package com.jetbrains.signatureverifier.crypt

class VerifySignatureResult(private val status: VerifySignatureStatus, private val message: String? = null) {
  val Status: VerifySignatureStatus
    get() = status

  val Message: String?
    get() = message

  val NotValid: Boolean
    get() = status != VerifySignatureStatus.Valid

  companion object {
    val Valid = VerifySignatureResult(VerifySignatureStatus.Valid)

    fun InvalidChain(message: String): VerifySignatureResult =
      VerifySignatureResult(VerifySignatureStatus.InvalidChain, message)
  }
}

enum class VerifySignatureStatus {
  Valid,
  InvalidSignature,
  InvalidChain,
  InvalidTimestamp
}
