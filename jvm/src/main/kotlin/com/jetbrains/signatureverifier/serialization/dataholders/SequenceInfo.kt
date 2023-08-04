package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class SequenceInfo(
  val content: List<EncodableInfo>
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive =
    content.toPrimitiveDLSequence()
}