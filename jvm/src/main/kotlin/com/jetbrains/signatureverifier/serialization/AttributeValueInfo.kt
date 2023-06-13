package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute

abstract class AttributeValueInfo: EncodableInfo {
  companion object {
    fun getInstance(attribute: Attribute): AttributeValueInfo {
      return when (attribute.attrType.id) {
        "1.2.840.113549.1.9.3" -> ContentTypeAttributeInfo(attribute)
        "1.2.840.113549.1.9.4" -> MessageDigestAttributeInfo(attribute)
        "1.3.6.1.4.1.311.2.1.11" -> MSCertExtensionsAttributeInfo(attribute)
        "1.3.6.1.4.1.311.2.1.12" -> MSCertificateTemplateV2AttributeInfo(attribute)
        else -> TODO("Make some default container")
      }
    }
  }

  abstract fun toAttributeDLSequence(): DLSequence

  override fun toPrimitive(): ASN1Primitive = toAttributeDLSequence().toASN1Primitive()
}