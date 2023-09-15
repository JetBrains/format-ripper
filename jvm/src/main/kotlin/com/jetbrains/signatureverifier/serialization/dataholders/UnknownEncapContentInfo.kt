package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toEncodableInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
data class UnknownEncapContentInfo(
  override val contentType: TextualInfo,
  val content: EncodableInfo?
) : EncapContentInfo() {

    constructor(contentInfo: ContentInfo) : this(
      TextualInfo.getInstance(contentInfo.contentType),
        contentInfo.content?.toASN1Primitive()?.toEncodableInfo()
    )

    override fun getContentPrimitive() = content?.toPrimitive()
}