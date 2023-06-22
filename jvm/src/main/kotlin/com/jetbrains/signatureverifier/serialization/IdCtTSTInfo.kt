package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
data class IdCtTSTInfo(
  val contentType: TextualInfo,
  val content: TextualInfo
) : EncapContentInfo {
  override fun toPrimitive(): ASN1Primitive =
    listOf(
      contentType.toPrimitive(),
      TaggedObjectInfo.getTaggedObjectWithMetaInfo(
        TaggedObjectMetaInfo(0, 1),
        content.toPrimitive()
      )
    ).toDLSequence()

  constructor(contentInfo: ContentInfo) : this(
    TextualInfo.getInstance(contentInfo.contentType),
    TextualInfo.getInstance(contentInfo.content)
  )
}