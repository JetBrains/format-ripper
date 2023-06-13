package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Primitive
import java.math.BigInteger

data class SignerIdentifierInfo (
  val issuerInfo: IssuerInfo,
  val serialNumber: BigInteger
): EncodableInfo{
  override fun toPrimitive(): ASN1Primitive {
    TODO("Not yet implemented")
  }
}
