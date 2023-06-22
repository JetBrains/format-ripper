package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class RSASignedDataInfo(
  val identifier: TextualInfo,
  val taggedObjectMetaInfo: TaggedObjectMetaInfo,
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
      val taggedObjectMetaInfo = TaggedObjectMetaInfo(tagged as ASN1TaggedObject)

      val sequence = tagged.baseObject as DLSequence

      val iterator = sequence.iterator()
      val version = TextualInfo.getInstance(iterator.next())
      val algorithms = (iterator.next() as DLSet).map { AlgorithmInfo(AlgorithmIdentifier.getInstance(it)) }
      val encapContentInfo = EncapContentInfo.getInstance(
        ContentInfo.getInstance(iterator.next())
      )
      val certificates = iterator.next().let {
        TaggedObjectInfo(
          TaggedObjectMetaInfo(it as DLTaggedObject),
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
        taggedObjectMetaInfo,
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
    TaggedObjectInfo.getTaggedObjectWithMetaInfo(
      taggedObjectMetaInfo,
      listOf(
        version.toPrimitive(),
        digestAlgorithmsInfo.toPrimitiveList().toDLSet(),
        encapContentInfo.toPrimitive(),
        certificates.toPrimitive(),
        counterSignatureInfos.toPrimitiveList().toDLSet()
      ).toDLSequence()
    )
  ).toDLSequence()

}