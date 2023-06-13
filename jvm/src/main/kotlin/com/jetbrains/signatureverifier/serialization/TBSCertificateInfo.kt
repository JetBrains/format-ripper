package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import java.util.*

data class TBSCertificateInfo(
  val version: Int,
  val serialNumber: String,
  val signatureAlgorithm: SignatureAlgorithmInfo,
  val issuer: IssuerInfo,
  val startDate: Date,
  val endDate: Date,
  val subject: IssuerInfo,
  val subjectAlgorithm: SignatureAlgorithmInfo,
  val subjectData: ByteArray,
  val extensions: List<ExtensionInfo>
) : EncodableInfo {
  private fun toDLSequence(): DLSequence {
    val sequence = ASN1EncodableVector()


    sequence.add(
      DLTaggedObject(
        true,
        0,
        ASN1Integer(version.toLong() - 1)
      )
    ) // -1 due to org.bouncycastle.asn1.x509.TBSCertificate.getVersionNumber

    sequence.add(ASN1Integer(serialNumber.toBigInteger()))
    sequence.add(signatureAlgorithm.toPrimitive())
    sequence.add(issuer.toPrimitive())

    val timeVector = ASN1EncodableVector()
    timeVector.addAll(
      listOf(
        ASN1UTCTime(startDate),
        ASN1UTCTime(endDate)
      ).toTypedArray()
    )
    sequence.add(DLSequence(timeVector))

    sequence.add(subject.toPrimitive())

    val subjectKeyVector = ASN1EncodableVector()
    subjectKeyVector.add(subjectAlgorithm.toPrimitive())
    subjectKeyVector.add(DERBitString(subjectData))
    sequence.add(DLSequence(subjectKeyVector))


    val extensionsVector = ASN1EncodableVector()
    extensionsVector.addAll(extensions.map {
      it.toPrimitive()
    }.toTypedArray())
    sequence.add(
      DLTaggedObject(
        true,
        3,
        DLSequence(extensionsVector)
      )
    )

    return DLSequence(sequence)
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}