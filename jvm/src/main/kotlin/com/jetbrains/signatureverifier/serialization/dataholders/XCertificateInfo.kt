package com.jetbrains.signatureverifier.serialization.dataholders

import kotlinx.serialization.Serializable
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CertificateHolder

@Serializable
sealed class XCertificateInfo : EncodableInfo {
  companion object {
    fun getInstance(obj: Any): XCertificateInfo =
      when (obj) {
        is X509CertificateHolder -> X509CertificateInfo.getInstance(obj)
        is X509AttributeCertificateHolder -> X509AttributeCertificateInfo.getInstance(obj)
        else -> throw IllegalArgumentException("Unexpected certificate type")
      }
  }
}