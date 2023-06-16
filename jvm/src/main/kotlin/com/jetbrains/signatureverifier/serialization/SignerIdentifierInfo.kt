package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cms.SignerId
import java.math.BigInteger

@Serializable
data class SignerIdentifierInfo(
  val issuerInfo: IssuerInfo,
  @Serializable(BigIntegerSerializer::class)
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
