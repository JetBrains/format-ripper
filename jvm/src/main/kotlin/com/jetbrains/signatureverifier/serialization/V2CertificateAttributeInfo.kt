package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class V2CertificateAttributeInfo(
  override val identifier: TextualInfo,
  val content: EncodableInfo
) : AttributeInfo {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.toEncodableInfo()
  )

  override fun toAttributeDLSequence(): DLSequence =
    listOf(identifier.toPrimitive(), content.toPrimitive()).toDLSequence()
}