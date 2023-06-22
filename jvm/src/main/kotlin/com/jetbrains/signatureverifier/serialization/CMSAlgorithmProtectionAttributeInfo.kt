package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class CMSAlgorithmProtectionAttributeInfo(
  val identifier: TextualInfo,
  val content: List<List<EncodableInfo>>
) : AttributeInfo {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.map { sequence ->
      (sequence as DLSequence).map {
        when (it) {
          is DLSequence -> AlgorithmInfo(AlgorithmIdentifier.getInstance(it))
          is DLTaggedObject -> TaggedObjectInfo(
            TaggedObjectMetaInfo(it),
            AlgorithmInfo(AlgorithmIdentifier.getInstance(it.baseObject))
          )

          else -> throw IllegalArgumentException("Unexpected algorithm protection identifier type")
        }
      }
    }
  )

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      content.map { it.toPrimitiveList().toDLSequence() }.toDLSet()
    ).toDLSequence()
}