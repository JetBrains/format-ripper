package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
data class UnknownEncapContentInfo(
  override val contentType: TextualInfo,
  val content: EncodableInfo?
) : EncapContentInfo {

  constructor(contentInfo: ContentInfo) : this(
    TextualInfo.getInstance(contentInfo.contentType),
    contentInfo.content?.toASN1Primitive()?.toEncodableInfo()
  )

  override fun toPrimitive(): ASN1Primitive =
    listOf(contentType.toPrimitive(), content?.toPrimitive()).toDLSequence()
}