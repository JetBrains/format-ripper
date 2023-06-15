package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
@Serializable
data class rdNInfo(
  val type: StringInfo,
  val value: StringInfo
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive =
    listToDLSequence(
      listOf(
        type.toPrimitive(),
        value.toPrimitive()
      )
    ).toASN1Primitive()
}
