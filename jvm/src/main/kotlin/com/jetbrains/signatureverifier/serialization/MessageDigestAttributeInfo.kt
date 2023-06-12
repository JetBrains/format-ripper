package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute

// 1.2.840.113549.1.9.4
data class MessageDigestAttributeInfo(
  val identifier: String,
  val value: DerStringInfo
) : AttributeValueInfo(identifier) {
  override fun toEncodable(): ASN1Encodable {
    val vector = ASN1EncodableVector()
    vector.add(value.toEncodableString())
    return Attribute(
        ASN1ObjectIdentifier(identifier),
        DERSet(vector)
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
      DerStringInfo(attribute.attributeValues.first())
  )
}