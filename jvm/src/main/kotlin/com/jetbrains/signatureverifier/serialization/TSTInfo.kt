package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject

@Serializable
data class TSTInfo(
  val identifier: StringInfo,
  val content: TaggedObjectInfo
) : EncodableInfo {

  constructor(sequence: DLSequence) : this(
    StringInfo.getInstance(sequence.first()),
    sequence.last().let {
      TaggedObjectInfo(
        TaggedObjectMetaInfo(it as DLTaggedObject),
        StringInfo.getInstance(it.baseObject)
      )
    }
  )

  override fun toPrimitive(): ASN1Primitive = listOf(
    identifier.toPrimitive(),
    content.toPrimitive()
  ).toDLSequence()
}