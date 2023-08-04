package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class MsCounterSignatureInfo(
  val version: Int,
  val algorithms: List<AlgorithmInfo>,
  val tstInfo: TSTInfo,
  val taggedCertificateInfo: TaggedObjectInfo,
  val counterSignatures: List<CounterSignatureInfo>

) : EncodableInfo {
  companion object {
    fun getInstance(sequence: DLSequence): MsCounterSignatureInfo {
      val iterator = sequence.iterator()

      val version = (iterator.next() as ASN1Integer).intValueExact()

      val algorithms = (iterator.next() as DLSet).map {
        AlgorithmInfo(
          AlgorithmIdentifier.getInstance(it)
        )
      }

      val tstInfo = TSTInfo(iterator.next() as DLSequence)

      val taggedCertificateInfo = iterator.next().let {
        TaggedObjectInfo(
          (it as DLTaggedObject).isExplicit,
          it.tagNo,
          SequenceInfo(
            (it.baseObject as DLSequence).map { certificateSequence ->
              CertificateInfo.getInstance(certificateSequence.toASN1Primitive())
            }
          )
        )
      }

      val counterSignatures = (iterator.next() as DLSet).map {
        CounterSignatureInfo.getInstance(it as DLSequence)
      }

      return MsCounterSignatureInfo(
        version,
        algorithms,
        tstInfo,
        taggedCertificateInfo,
        counterSignatures
      )
    }

  }

  override fun toPrimitive(): ASN1Primitive = listOf(
    ASN1Integer(version.toLong()),
    algorithms.toPrimitiveDLSet(),
    tstInfo.toPrimitive(),
    taggedCertificateInfo.toPrimitive(),
    counterSignatures.toPrimitiveDLSet()
  ).toDLSequence()
}