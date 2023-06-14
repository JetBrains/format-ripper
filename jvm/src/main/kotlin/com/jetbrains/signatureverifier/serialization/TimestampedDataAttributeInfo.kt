package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.10.3.28
data class TimestampedDataAttributeInfo(
  val identifier: StringInfo,
  val content: StringInfo
): AttributeValueInfo() {

  override fun toAttributeDLSequence(): DLSequence = listToDLSequence(
    listOf(
      identifier.toPrimitive(),
      listToDLSet(listOf(content.toPrimitive()))
    )
  )

  constructor(attribute: Attribute): this(
    StringInfo.getInstance(attribute.attrType),
    StringInfo.getInstance(attribute.attributeValues.first())
  )
}