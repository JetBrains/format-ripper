package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.10.3.28
@Serializable
data class TimestampedDataAttributeInfo(
  val identifier: StringInfo,
  val content: List<StringInfo>
): AttributeInfo {

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      content.map { it.toPrimitive() }.toDLSet()
    ).toDLSequence()

  constructor(attribute: Attribute): this(
    StringInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { StringInfo.getInstance(it) }
  )
}