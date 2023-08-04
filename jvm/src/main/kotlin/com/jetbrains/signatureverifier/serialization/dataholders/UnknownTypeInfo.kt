package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class UnknownTypeInfo<T : ASN1Primitive>(
  @Serializable(ByteArraySerializer::class)
  val content: ByteArray
) : EncodableInfo {
  constructor(obj: T) : this(obj.encoded)

  override fun toPrimitive(): ASN1Primitive = ASN1Primitive.fromByteArray(content)

}