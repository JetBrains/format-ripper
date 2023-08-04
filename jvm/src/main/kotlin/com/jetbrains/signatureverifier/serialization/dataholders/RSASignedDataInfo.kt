package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class RSASignedDataInfo(
  val identifier: TextualInfo,
  val explicit: Boolean,
  val tagNo: Int,
  val version: TextualInfo,
  val digestAlgorithmsInfo: List<AlgorithmInfo>,
  val encapContentInfo: EncapContentInfo,
  val certificates: TaggedObjectInfo, //List<CertificateInfo>,
//  val crls: List<EncodableInfo>?,
  val counterSignatureInfos: List<CounterSignatureInfo>
) : EncodableInfo {
  companion object {
    fun getInstance(originalSequence: ASN1Sequence): RSASignedDataInfo {
      val identifier = TextualInfo.getInstance(originalSequence.first())

      val tagged = originalSequence.getObjectAt(1)
      val tagNo = (tagged as ASN1TaggedObject).tagNo
      val explicit = tagged.isExplicit

      val sequence = tagged.baseObject as DLSequence

      val iterator = sequence.iterator()
      val version = TextualInfo.getInstance(iterator.next())
      val algorithms = (iterator.next() as DLSet).map { AlgorithmInfo(AlgorithmIdentifier.getInstance(it)) }
      val encapContentInfo = EncapContentInfo.getInstance(
        ContentInfo.getInstance(iterator.next())
      )

      val certificates = iterator.next().let {
        TaggedObjectInfo(
          (it as DLTaggedObject).isExplicit,
          it.tagNo,
          SequenceInfo(
            (it.baseObject as DLSequence).map { obj ->
              CertificateInfo.getInstance(obj.toASN1Primitive())
            }
          )
        )
      }

      val counterSignatures = (iterator.next() as DLSet).map {
        CounterSignatureInfo.getInstance(it as DLSequence)
      }

      return RSASignedDataInfo(
        identifier,
        explicit,
        tagNo,
        version,
        algorithms,
        encapContentInfo,
        certificates,
        counterSignatures
      )
    }
  }

  override fun toPrimitive(): ASN1Primitive = listOf(
    identifier.toPrimitive(),
    TaggedObjectInfo.getTaggedObject(
      explicit,
      tagNo,
      listOf(
        version.toPrimitive(),
        digestAlgorithmsInfo.toPrimitiveDLSet(),
        encapContentInfo.toPrimitive(),
        certificates.toPrimitive(),
        counterSignatureInfos.toPrimitiveDLSet()
      ).toDLSequence()
    )
  ).toDLSequence()

}