package com.jetbrains.signatureverifier.serialization.dataholders

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
data class IdCtTSTInfo(
  override val contentType: TextualInfo,
  val content: TextualInfo
) : EncapContentInfo() {

  constructor(contentInfo: ContentInfo) : this(
    TextualInfo.getInstance(contentInfo.contentType),
    TextualInfo.getInstance(contentInfo.content)
  )

  override fun getContentPrimitive() = content.toPrimitive()
}