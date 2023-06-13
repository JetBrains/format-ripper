package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.11
data class MSCertExtensionsAttributeInfo(
  val identifier: String,
  val value: List<List<String>>
) : AttributeValueInfo() {
  override fun toAttribute(): Attribute {
    val vector = ASN1EncodableVector()
    vector.addAll(value.map {
      val v = ASN1EncodableVector()
      v.addAll(
        it.map { s -> ASN1ObjectIdentifier(s) }.toTypedArray()
      )
      DLSequence(v)
    }.toTypedArray())
    return Attribute(
      ASN1ObjectIdentifier(identifier),
      DLSet(vector)
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
    attribute.attributeValues.map { (it as DLSequence).map { s -> s.toString() } }
  )
}