package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.11
data class MSCertExtensionsAttributeInfo(
  val identifier: String,
  val value: List<String>
) : AttributeValueInfo(identifier) {
  override fun toEncodable(): ASN1Encodable {
    val vector = ASN1EncodableVector()
    vector.addAll(value.map { ASN1ObjectIdentifier(it) }.toTypedArray())
    return Attribute(
      ASN1ObjectIdentifier(identifier),
      DERSet(vector)
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
    attribute.attributeValues.map { it.toString() }
  )
}