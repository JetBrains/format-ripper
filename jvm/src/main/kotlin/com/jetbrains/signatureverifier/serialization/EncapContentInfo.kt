package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class EncapContentInfo(
  val contentType: StringInfo,
  val imageDataObjIdInfo: ImageDataObjIdInfo,
  val hashAlgorithmInfo: AlgorithmInfo,
  val contentHash: StringInfo
) : EncodableInfo {
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

  constructor(contentInfo: ContentInfo) : this(
    StringInfo.getInstance(contentInfo.contentType),
    ImageDataObjIdInfo.getInstance((contentInfo.content as DLSequence).first() as DLSequence),
    AlgorithmInfo(
      (AlgorithmIdentifier.getInstance(
        ((contentInfo.content as DLSequence).last() as DLSequence).first()
      ))
    ),
    StringInfo.getInstance(((contentInfo.content as DLSequence).last() as DLSequence).last())
  )
}