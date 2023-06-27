package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
sealed interface EncapContentInfo : EncodableInfo {
  companion object {
    fun getInstance(contentInfo: ContentInfo): EncapContentInfo {
      return when (contentInfo.contentType.id) {
        "1.3.6.1.4.1.311.2.1.4" -> PeEncapContentInfo.getInstance(contentInfo)
        "1.2.840.113549.1.7.1" -> RsaEncapContentInfo(contentInfo)
        "1.2.840.113549.1.9.16.1.4" -> IdCtTSTInfo(contentInfo)
        else -> UnknownEncapContentInfo(contentInfo)
      }
    }
  }

  val contentType: TextualInfo
}