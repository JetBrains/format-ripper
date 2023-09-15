package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toEncodableInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class UnknownAttributeInfo(
  override val identifier: TextualInfo,
  val content: EncodableInfo
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.toEncodableInfo()
  )

  override fun getPrimitiveContent() = content.toPrimitive()
}