package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
data class RsaEncapContentInfo(
  val contentType: TextualInfo,
  val content: TextualInfo?
) : EncapContentInfo {
  override fun toPrimitive(): ASN1Primitive =
    listOf(contentType.toPrimitive(), content?.toPrimitive()).toDLSequence()

  constructor(contentInfo: ContentInfo) : this(
    TextualInfo.getInstance(contentInfo.contentType),
    contentInfo.content?.let { TextualInfo.getInstance(it) }
  )
}