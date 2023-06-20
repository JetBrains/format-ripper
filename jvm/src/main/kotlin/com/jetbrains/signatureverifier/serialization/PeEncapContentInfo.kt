package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class PeEncapContentInfo(
  val contentType: StringInfo,
  val imageDataObjIdInfo: ImageDataObjIdInfo,
  val hashAlgorithmInfo: AlgorithmInfo,
  val contentHash: StringInfo
) : EncapContentInfo {
  companion object {
    fun getInstance(contentInfo: ContentInfo): PeEncapContentInfo =
      (contentInfo.content as DLSequence).let { contentSequence ->
        (contentSequence.getObjectAt(1) as DLSequence).let { algorithmSequence ->
          PeEncapContentInfo(
            StringInfo.getInstance(contentInfo.contentType),
            ImageDataObjIdInfo.getInstance(contentSequence.first() as DLSequence),
            AlgorithmInfo(
              (AlgorithmIdentifier.getInstance(
                algorithmSequence.first()
              ))
            ),
            StringInfo.getInstance(algorithmSequence.getObjectAt(1))
          )
        }
      }
  }

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      contentType.toPrimitive(),
      TaggedObjectInfo.getTaggedObjectWithMetaInfo(
        TaggedObjectMetaInfo(0, 1),
        listOf(
          imageDataObjIdInfo.toPrimitive(),
          listOf(
            hashAlgorithmInfo.toPrimitive(),
            contentHash.toPrimitive()
          ).toDLSequence()
        ).toDLSequence()
      ),
    ).toDLSequence()
}