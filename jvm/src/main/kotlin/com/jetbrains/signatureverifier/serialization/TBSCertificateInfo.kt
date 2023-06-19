package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.cert.X509CertificateHolder
import java.util.*

@Serializable
data class TBSCertificateInfo(
  val version: Int,
  val serialNumber: String,
  val signatureAlgorithm: AlgorithmInfo,
  val issuer: IssuerInfo,
  @Serializable(DateSerializer::class)
  val startDate: Date,
  @Serializable(DateSerializer::class)
  val endDate: Date,
  val subject: IssuerInfo,
  val subjectAlgorithm: AlgorithmInfo,
  val subjectData: StringInfo,
  val extensions: List<ExtensionInfo>
) : EncodableInfo {
  companion object {
    fun getInstance(certificateHolder: X509CertificateHolder): TBSCertificateInfo =
      TBSCertificateInfo(
        certificateHolder.versionNumber,
        certificateHolder.serialNumber.toString(),
        AlgorithmInfo(certificateHolder.signatureAlgorithm),
        IssuerInfo(certificateHolder.issuer),
        certificateHolder.notBefore,
        certificateHolder.notAfter,
        IssuerInfo(certificateHolder.subject),
        AlgorithmInfo(certificateHolder.subjectPublicKeyInfo.algorithm),
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

    listOf(
      DLTaggedObject(
        true, 0, ASN1Integer(version.toLong() - 1)
      ),
      ASN1Integer(serialNumber.toBigInteger()),
      signatureAlgorithm.toPrimitive(),
      issuer.toPrimitive(),

      listOf(
        ASN1UTCTime(startDate),
        ASN1UTCTime(endDate)
      ).toDLSequence(),
      subject.toPrimitive(),
      listOf(
        subjectAlgorithm.toPrimitive(),
        subjectData.toPrimitive()
      ).toDLSequence(),
      DLTaggedObject(
        true,
        3,
        extensions.map {
          it.toPrimitive()
        }.toDLSequence()
      )
    ).toDLSequence()

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}