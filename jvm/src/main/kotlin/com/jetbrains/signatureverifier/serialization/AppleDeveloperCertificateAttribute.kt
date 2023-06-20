package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class AppleDeveloperCertificateAttribute(
  val identifier: StringInfo,
  val content: List<StringInfo>
) : AttributeInfo {
  override fun toAttributeDLSequence(): DLSequence = listOf(
    identifier.toPrimitive(),
    content.map { it.toPrimitive() }.toDLSet()
  ).toDLSequence()

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map {
      StringInfo.getInstance(it)
    }
  )
}