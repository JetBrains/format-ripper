package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive

@Serializable
data class ObjectDigestInfo(
  val digestedObjectType: TextualInfo,
  val otherObjectTypeID: TextualInfo?,
  val digestAlgorithmInfo: AlgorithmInfo,
  val objectDigest: TextualInfo
) : EncodableInfo {

  constructor(info: org.bouncycastle.asn1.x509.ObjectDigestInfo) : this(
    TextualInfo.getInstance(info.digestedObjectType),
    info.otherObjectTypeID?.let { TextualInfo.getInstance(it) },
    AlgorithmInfo(info.digestAlgorithm),
    TextualInfo.getInstance(info.objectDigest)
  )

  override fun toPrimitive(): ASN1Primitive = listOf(
    digestedObjectType.toPrimitive(),
    otherObjectTypeID?.toPrimitive(),
    digestAlgorithmInfo.toPrimitive(),
    objectDigest.toPrimitive()
  ).toDLSequence()
}