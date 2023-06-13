package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import java.util.*
import org.bouncycastle.asn1.ASN1Encoding

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