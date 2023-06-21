package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class rdNInfo(
  val type: TextualInfo,
  val value: TextualInfo
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive =
    listOf(
      type.toPrimitive(),
      value.toPrimitive()
    ).toDLSequence().toASN1Primitive()
}
