package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.DateSerializer
import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.cert.X509CertificateHolder
import java.util.*

@Serializable
data class X509CertificateInfo(
  val version: Int,
  val serialNumber: String,
  val signatureAlgorithm: AlgorithmInfo,
  val issuer: X500NameInfo,
  @Serializable(DateSerializer::class)
  val startDate: Date,
  @Serializable(DateSerializer::class)
  val endDate: Date,
  val subject: X500NameInfo,
  val subjectAlgorithm: AlgorithmInfo,
  val subjectData: TextualInfo,
  val extensions: List<ExtensionInfo>?
) : XCertificateInfo() {
  companion object {
    fun getInstance(certificateHolder: X509CertificateHolder): X509CertificateInfo =
      X509CertificateInfo(
        certificateHolder.versionNumber,
        certificateHolder.serialNumber.toString(),
        AlgorithmInfo(certificateHolder.signatureAlgorithm),
        X500NameInfo(certificateHolder.issuer),
        certificateHolder.notBefore,
        certificateHolder.notAfter,
        X500NameInfo(certificateHolder.subject),
        AlgorithmInfo(certificateHolder.subjectPublicKeyInfo.algorithm),
        TextualInfo.getInstance(certificateHolder.subjectPublicKeyInfo.publicKeyData),
        certificateHolder.extensions?.let {
          it.extensionOIDs.map {oid->
            val extension = certificateHolder.extensions.getExtension(oid)
            ExtensionInfo(
              TextualInfo.getInstance(extension.extnId),
              certificateHolder.extensions.criticalExtensionOIDs.contains(extension.extnId),
              TextualInfo.getInstance(extension.extnValue)
            )
          }
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
      extensions?.let {
        DLTaggedObject(
          true,
          3,
          it.toPrimitiveDLSequence()
        )
      }
    ).toDLSequence()

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}