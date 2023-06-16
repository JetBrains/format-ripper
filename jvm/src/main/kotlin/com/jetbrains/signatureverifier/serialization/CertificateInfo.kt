package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.Store
@Serializable
data class CertificateInfo(
  val tbsCertificateInfo: TBSCertificateInfo,
  val signatureAlgorithm: AlgorithmInfo,
  val signatureData: StringInfo
) : EncodableInfo {
  companion object {
    fun getInstance(certificateHolder: X509CertificateHolder) = CertificateInfo(
      TBSCertificateInfo.getInstance(certificateHolder),
      AlgorithmInfo(certificateHolder.signatureAlgorithm),
      StringInfo.getInstance(DERBitString(certificateHolder.signature))
    )

  }

  private fun toDlSequence(): DLSequence = listToDLSequence(
    listOf(
      tbsCertificateInfo.toPrimitive(),
      signatureAlgorithm.toPrimitive(),
      signatureData.toPrimitive()
    )
  )

  fun toX509CertificateHolder() = X509CertificateHolder(
    Certificate.getInstance(toPrimitive())
  )

  override fun toPrimitive(): ASN1Primitive =
    toDlSequence().toASN1Primitive()
}

fun recreateCertificatesFromStore(store: Store<X509CertificateHolder>): ASN1Set =
  listToDLSet(store.getMatches(null).toList().map { it.toASN1Structure() })