package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cms.SignerId
import java.math.BigInteger

data class SignerIdentifierInfo(
  val issuerInfo: IssuerInfo,
  val serialNumber: BigInteger
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive = listToDLSequence(
    listOf(
      issuerInfo.toPrimitive(),
      ASN1Integer(serialNumber)
    )
  )

  constructor(sid: SignerId) : this(
    IssuerInfo(sid.issuer),
    sid.serialNumber
  )
}
