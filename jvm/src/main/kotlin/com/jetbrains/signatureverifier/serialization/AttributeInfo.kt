package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Primitive

data class AttributeInfo(
  val id: StringInfo,
  val value: AttributeValueInfo
): EncodableInfo {
  override fun toPrimitive(): ASN1Primitive {
    TODO("Not yet implemented")
  }
}

