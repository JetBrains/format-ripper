package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.11
@Serializable
data class MSCertExtensionsAttributeInfo(
  val identifier: TextualInfo,
  val content: List<List<TextualInfo>>
) : AttributeInfo {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { (it as DLSequence).map { s -> TextualInfo.getInstance(s) } }
  )

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      content.map {
        it.map { s -> s.toPrimitive() }.toDLSequence()
      }.toDLSet()
    ).toDLSequence()
}