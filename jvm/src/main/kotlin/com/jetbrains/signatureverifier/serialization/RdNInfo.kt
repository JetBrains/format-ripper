package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence

data class rdNInfo(
  val type: String,
  val value: StringInfo
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive {
    val sequense = ASN1EncodableVector()

    val string = value.toPrimitive()


    sequense.addAll(
      listOf(
        ASN1ObjectIdentifier(type),
        string
      ).toTypedArray()
    )
    return DLSequence(sequense).toASN1Primitive()
  }

}