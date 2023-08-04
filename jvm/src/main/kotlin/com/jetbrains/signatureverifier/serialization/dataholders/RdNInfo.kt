package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class RdNInfo(
  val type: TextualInfo,
  val value: TextualInfo
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive =
    listOf(
      type.toPrimitive(),
      value.toPrimitive()
    ).toDLSequence().toASN1Primitive()
}
