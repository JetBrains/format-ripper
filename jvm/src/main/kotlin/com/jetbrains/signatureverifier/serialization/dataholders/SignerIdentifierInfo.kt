package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.BigIntegerSerializer
import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cms.SignerId
import java.math.BigInteger

@Serializable
data class SignerIdentifierInfo(
  val issuerInfo: X500NameInfo,
  @Serializable(BigIntegerSerializer::class)
  val serialNumber: BigInteger
) : EncodableInfo {

  constructor(sid: SignerId) : this(
    X500NameInfo(sid.issuer),
    sid.serialNumber
  )

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      issuerInfo.toPrimitive(),
      ASN1Integer(serialNumber)
    ).toDLSequence()
}
