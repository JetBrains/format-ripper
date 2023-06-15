package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute

// 1.2.840.113549.1.9.3
@Serializable
data class ContentTypeAttributeInfo(
  val identifier: StringInfo,
  val value: StringInfo
) : AttributeValueInfo() {
  override fun toAttributeDLSequence(): DLSequence = listToDLSequence(
    listOf(
      identifier.toPrimitive(),
      listToDLSet(listOf(value.toPrimitive()))
    )
  )


  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    StringInfo.getInstance(attribute.attributeValues.first())
  )
}