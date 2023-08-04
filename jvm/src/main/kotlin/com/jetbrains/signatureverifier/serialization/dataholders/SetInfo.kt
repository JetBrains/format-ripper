package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class SetInfo(
  val content: List<EncodableInfo>
) : EncodableInfo {

  override fun toPrimitive(): ASN1Primitive =
    content.toPrimitiveDLSet()
}