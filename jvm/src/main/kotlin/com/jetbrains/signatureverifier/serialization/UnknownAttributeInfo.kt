package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class UnknownAttributeInfo(
  val identifier: StringInfo,
  val content: ByteArray
) : AttributeInfo() {

  override fun toAttributeDLSequence(): DLSequence = DLSequence.getInstance(content) as DLSequence

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    attribute.getEncoded("DER")
  )
}