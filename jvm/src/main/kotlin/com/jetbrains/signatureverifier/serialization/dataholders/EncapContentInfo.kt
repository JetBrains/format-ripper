package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.ContentInfo

@Serializable
sealed class EncapContentInfo : EncodableInfo {
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

    abstract fun getContentPrimitive(): ASN1Primitive?
    abstract val contentType: TextualInfo

    override fun toPrimitive(): ASN1Primitive =
        listOf(
            contentType.toPrimitive(),
            getContentPrimitive()?.let {
              TaggedObjectInfo.getTaggedObject(
                true,
                0,
                it
              )
            }
        ).toDLSequence()
}