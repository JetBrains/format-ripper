package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import java.util.*
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.cert.X509CertificateHolder

data class TBSCertificateInfo(
  val version: Int,
  val serialNumber: String,
  val signatureAlgorithm: SignatureAlgorithmInfo,
  val issuer: IssuerInfo,
  val startDate: Date,
  val endDate: Date,
  val subject: IssuerInfo,
  val subjectAlgorithm: SignatureAlgorithmInfo,
  val subjectData: StringInfo,
  val extensions: List<ExtensionInfo>
) : EncodableInfo {
  companion object {
    fun getInstance(certificateHolder: X509CertificateHolder): TBSCertificateInfo =
      TBSCertificateInfo(
        certificateHolder.versionNumber,
        certificateHolder.serialNumber.toString(),
        SignatureAlgorithmInfo(certificateHolder.signatureAlgorithm),
        IssuerInfo(certificateHolder.issuer),
        certificateHolder.notBefore,
        certificateHolder.notAfter,
        IssuerInfo(certificateHolder.subject),
        SignatureAlgorithmInfo(certificateHolder.subjectPublicKeyInfo.algorithm),
        StringInfo.getInstance(certificateHolder.subjectPublicKeyInfo.publicKeyData),
        certificateHolder.extensions.extensionOIDs.map {
          val extension = certificateHolder.extensions.getExtension(it)
          ExtensionInfo(
            StringInfo.getInstance(extension.extnId),
            certificateHolder.extensions.criticalExtensionOIDs.contains(extension.extnId),
            StringInfo.getInstance(extension.extnValue)
          )
        }
      )
  }

  private fun toDLSequence(): DLSequence =
    listToDLSequence(
      listOf(
        DLTaggedObject(
          true, 0, ASN1Integer(version.toLong() - 1)
        ),
        ASN1Integer(serialNumber.toBigInteger()),
        signatureAlgorithm.toPrimitive(),
        issuer.toPrimitive(),
        listToDLSequence(
          listOf(
            ASN1UTCTime(startDate),
            ASN1UTCTime(endDate)
          )
        ),
        subject.toPrimitive(),
        listToDLSequence(
          listOf(
            subjectAlgorithm.toPrimitive(),
            subjectData.toPrimitive()
          )
        ),
        DLTaggedObject(
          true,
          3,
          listToDLSequence(extensions.map {
            it.toPrimitive()
          })
        )
      )
    )

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}