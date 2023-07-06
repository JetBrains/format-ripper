package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class PublicKeyInfrastructureAttributeInfo(
  override val identifier: TextualInfo,
  val content: EncodableInfo
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.toEncodableInfo()
  )

  override fun getPrimitiveContent() = content.toPrimitive()
}