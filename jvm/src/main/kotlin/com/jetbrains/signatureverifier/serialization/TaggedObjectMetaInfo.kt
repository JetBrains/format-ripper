package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1TaggedObject

@Serializable
data class TaggedObjectMetaInfo(
  val tagNo: Int,
  val explicitness: Int
) {
  constructor(obj: ASN1TaggedObject) : this(obj.tagNo, obj.getExplicitness())
}