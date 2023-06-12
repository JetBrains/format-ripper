package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.12
data class MSCertificateTemplateV2AttributeInfo(
  val identifier: String,
  val value: List<TaggedObjectInfo>
) : AttributeValueInfo(identifier) {
  companion object {
    data class TaggedObjectInfo(
      val tagNo1: Int,
      val tagNo2: Int,
      val content: DerStringInfo
    ) {
      constructor(value: DLTaggedObject) : this(
        value.tagNo,
        (value.baseObject as DLTaggedObject).tagNo,
          DerStringInfo((value.baseObject as DLTaggedObject).baseObject)
      )
      fun toEncodable() = DLTaggedObject(
          tagNo1,
          DLTaggedObject(
              tagNo2,
              content.toEncodableString()
          )
      )
    }
  }

  override fun toEncodable(): ASN1Encodable {
    val vector = ASN1EncodableVector()
    vector.addAll(value.map { it.toEncodable() }.toTypedArray())
    return Attribute(
        ASN1ObjectIdentifier(identifier),
        DERSet(DLSequence(vector))
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
    attribute.attributeValues.map {
      TaggedObjectInfo(it as DLTaggedObject)
    }
  )
}