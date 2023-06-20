package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Primitive
import java.math.BigInteger

@Serializable
data class ObjectDigestInfo(
  @Serializable(BigIntegerSerializer::class)
  val digestedObjectType: BigInteger,
  val otherObjectTypeID: StringInfo?,
  val digestAlgorithmInfo: AlgorithmInfo,
  val objectDigest: StringInfo
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive = listOf(
    ASN1Enumerated(digestedObjectType),
    otherObjectTypeID?.toPrimitive(),
    digestAlgorithmInfo.toPrimitive(),
    objectDigest.toPrimitive()
  ).toDLSequence()

  constructor(info: org.bouncycastle.asn1.x509.ObjectDigestInfo) : this(
    info.digestedObjectType.value,
    info.otherObjectTypeID?.let { StringInfo.getInstance(it) },
    AlgorithmInfo(info.digestAlgorithm),
    StringInfo.getInstance(info.objectDigest)
  )
}