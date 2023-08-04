package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AttributeCertificate
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.Store

@Serializable
data class CertificateInfo(
  val xCertificateInfo: XCertificateInfo,
  val signatureAlgorithm: AlgorithmInfo,
  val signatureData: TextualInfo
) : EncodableInfo {
  companion object {
    fun getInstance(certificateHolder: X509CertificateHolder) = CertificateInfo(
      XCertificateInfo.getInstance(certificateHolder),
      AlgorithmInfo(certificateHolder.signatureAlgorithm),
      TextualInfo.getInstance(DERBitString(certificateHolder.signature))
    )

    fun getInstance(certificateHolder: X509AttributeCertificateHolder) = CertificateInfo(
      XCertificateInfo.getInstance(certificateHolder),
      AlgorithmInfo(certificateHolder.signatureAlgorithm),
      TextualInfo.getInstance(DERBitString(certificateHolder.signature))
    )

    fun getInstance(obj: ASN1Object): EncodableInfo = when (obj) {
      is DLSequence -> {
        getInstance(
          X509CertificateHolder(
            Certificate.getInstance(
              obj
            )
          )
        )
      }

      is DLTaggedObject -> {
        TaggedObjectInfo(
          obj.isExplicit,
          obj.tagNo,
          getInstance(
            X509AttributeCertificateHolder(
              AttributeCertificate.getInstance(
                obj.baseObject
              )
            )
          )
        )
      }

      else -> throw IllegalArgumentException("Unexpected object type")
    }
  }

  private fun toDlSequence(): DLSequence =
    listOf(
      xCertificateInfo.toPrimitive(),
      signatureAlgorithm.toPrimitive(),
      signatureData.toPrimitive()
    ).toDLSequence()

  fun toX509CertificateHolder() = X509CertificateHolder(
    Certificate.getInstance(toPrimitive())
  )

  override fun toPrimitive(): ASN1Primitive =
    toDlSequence().toASN1Primitive()
}

fun recreateCertificatesFromStore(store: Store<X509CertificateHolder>): ASN1Set =
  store.getMatches(null).toList().map { it.toASN1Structure() }.toDLSet()