package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.12
@Serializable
data class MSCertificateTemplateV2AttributeInfo(
  val identifier: StringInfo,
  val value: List<TaggedObjectInfo>
) : AttributeInfo {

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
        listOf(
          value.map { it.toPrimitive() }.toDLSequence()
        ).toDLSet()
    ).toDLSequence()

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    (attribute.attributeValues.first() as DLSequence).map {
      TaggedObjectInfo(
        TaggedObjectMetaInfo(it as DLTaggedObject),
        TaggedObjectInfo(
          TaggedObjectMetaInfo(it.baseObject as DLTaggedObject),
          StringInfo.getInstance((it.baseObject as DLTaggedObject).baseObject)
        )
      )
    }
  )

}