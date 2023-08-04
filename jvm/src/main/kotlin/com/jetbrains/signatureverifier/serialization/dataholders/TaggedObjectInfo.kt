package com.jetbrains.signatureverifier.serialization.dataholders

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLTaggedObject

@Serializable
data class TaggedObjectInfo(
  val explicit: Boolean,
  val tagNo: Int,
  val content: EncodableInfo
) : EncodableInfo {
  companion object {
    fun getTaggedObject(
      explicit: Boolean,
      tagNo: Int,
      content: ASN1Encodable
    ): DLTaggedObject = DLTaggedObject(explicit, tagNo, content)
  }

  override fun toPrimitive(): ASN1Primitive = getTaggedObject(explicit, tagNo, content.toPrimitive()).toASN1Primitive()

}