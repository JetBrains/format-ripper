package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.cms.Attribute

abstract class AttributeValueInfo(identifier: String) {
  companion object {
    fun getInstance(attribute: Attribute): AttributeValueInfo {
      return when (attribute.attrType.id) {
        "1.2.840.113549.1.9.3" -> ContentTypeAttributeInfo(attribute)
        else -> TODO("Make some default container")
      }
    }
  }

  abstract fun toEncodable(): ASN1Encodable
}