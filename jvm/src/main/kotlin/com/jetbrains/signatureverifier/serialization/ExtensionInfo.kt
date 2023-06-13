package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*

data class ExtensionInfo(
  val key: StringInfo,
  val critical: Boolean,
  val value: StringInfo
) : EncodableInfo {
  private fun toDLSequence(): DLSequence {
    val vector = ASN1EncodableVector()
    vector.add(key.toPrimitive())
    if (critical) {
      vector.add(ASN1Boolean.TRUE)
    }
    vector.add(value.toPrimitive())

    return DLSequence(vector)
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}