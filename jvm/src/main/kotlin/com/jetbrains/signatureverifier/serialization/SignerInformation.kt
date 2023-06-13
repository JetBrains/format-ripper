package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Primitive

data class SignerInformation(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: SignatureAlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>
):EncodableInfo {
  override fun toPrimitive(): ASN1Primitive {
    TODO("Not yet implemented")
  }
}


