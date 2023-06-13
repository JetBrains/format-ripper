package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute

class CustomDLTaggedObject(tagNo: Int, obj: ASN1Primitive?) :
  DLTaggedObject(true, tagNo, obj) {
  override fun isExplicit(): Boolean {
    return true
  }
}

// 1.3.6.1.4.1.311.2.1.12
data class MSCertificateTemplateV2AttributeInfo(
  val identifier: String,
  val value: List<TaggedObjectInfo>
) : AttributeValueInfo() {
  companion object {

    data class TaggedObjectInfo(
      val metaInfo1: TaggedObjectMetaInfo,
      val metaInfo2: TaggedObjectMetaInfo,
      val content: DerStringInfo
    ) {
      constructor(value: DLTaggedObject) : this(
        TaggedObjectMetaInfo(value),
        TaggedObjectMetaInfo(value.baseObject as DLTaggedObject),
        DerStringInfo.getInstance((value.baseObject as DLTaggedObject).baseObject)
      )

      fun toEncodable() = TaggedObjectMetaInfo.getTaggedObjectWithMetaInfo(
        metaInfo1,
        TaggedObjectMetaInfo.getTaggedObjectWithMetaInfo(
          metaInfo2,
          content.toEncodableString()
        )
      )
    }
  }

  override fun toAttribute(): Attribute {
    val vector = ASN1EncodableVector()
    vector.addAll(value.map { it.toEncodable() }.toTypedArray())
    return Attribute(
      ASN1ObjectIdentifier(identifier),
      DLSet(DLSequence(vector))
    )
  }

  constructor(attribute: Attribute) : this(
    attribute.attrType.toString(),
    (attribute.attributeValues.first() as DLSequence).map {
      TaggedObjectInfo(it as DLTaggedObject)
    }
  )
}