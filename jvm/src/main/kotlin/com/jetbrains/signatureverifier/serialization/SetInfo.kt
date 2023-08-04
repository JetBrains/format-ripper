package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class SetInfo(
  val content: List<EncodableInfo>
) : EncodableInfo {

  override fun toPrimitive(): ASN1Primitive =
    content.toPrimitiveDLSet()
}