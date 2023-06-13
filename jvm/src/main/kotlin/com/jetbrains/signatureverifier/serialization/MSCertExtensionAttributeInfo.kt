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
  val identifier: StringInfo,
  val value: List<List<StringInfo>>
) : AttributeValueInfo() {
  override fun toAttributeDLSequence(): DLSequence = listToDLSequence(
    listOf(
      identifier.toPrimitive(),
      listToDLSet(
        value.map {
          listToDLSequence(
            it.map { s -> s.toPrimitive() }
          )
        }
      )
    )
  )

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { (it as DLSequence).map { s -> StringInfo.getInstance(s) } }
  )
}