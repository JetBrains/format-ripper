package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.Attribute

// 1.2.840.113549.1.9.3
data class ContentTypeAttributeInfo(
  val identifier: String,
  val value: String
) : AttributeValueInfo() {
  override fun toAttribute(): Attribute {
    val vector = ASN1EncodableVector()
    vector.add(ASN1ObjectIdentifier(value))
    return Attribute(
      ASN1ObjectIdentifier(identifier),
      DLSet(vector)
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
    attribute.attributeValues.first().toString()
  )
}