package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLTaggedObject

data class TaggedObjectInfo(
  val metaInfo: TaggedObjectMetaInfo,
  val content: EncodableInfo
) : EncodableInfo {
  companion object {
    private const val DECLARED_EXPLICIT = 1
    private const val DECLARED_IMPLICIT = 2
    private const val PARSED_EXPLICIT = 3
    private const val PARSED_IMPLICIT = 4

    /**
     * Hack to get same explicitness as in original
     */
    private fun getTaggedObjectWithMetaInfo(
      metaInfo: TaggedObjectMetaInfo,
      content: ASN1Encodable
    ): DLTaggedObject = when (metaInfo.explicitness) {
      DECLARED_EXPLICIT -> DLTaggedObject(true, metaInfo.tagNo, content)
      DECLARED_IMPLICIT -> DLTaggedObject(false, metaInfo.tagNo, content)

      PARSED_EXPLICIT -> DLTaggedObject.getInstance(
        DLTaggedObject(true, metaInfo.tagNo, content).encoded
      ) as DLTaggedObject

      PARSED_IMPLICIT -> DLTaggedObject.getInstance(
        DLTaggedObject(false, metaInfo.tagNo, content).encoded
      ) as DLTaggedObject

      else -> throw Exception("Tagged object explicitness can only be 1, 2, 3 or 4")
    }
  }

  override fun toPrimitive(): ASN1Primitive =
    getTaggedObjectWithMetaInfo(metaInfo, content.toPrimitive()).toASN1Primitive()

}