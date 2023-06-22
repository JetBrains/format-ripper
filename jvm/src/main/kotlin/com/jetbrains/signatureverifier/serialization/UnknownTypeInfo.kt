package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class UnknownTypeInfo<T : ASN1Primitive>(
  val content: String
) : EncodableInfo {
  constructor(obj: T) : this(obj.encoded.toHexString())

  override fun toPrimitive(): ASN1Primitive = ASN1Primitive.fromByteArray(content.toByteArray())

}