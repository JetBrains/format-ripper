package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.12
@Serializable
data class MSCertificateTemplateV2AttributeInfo(
  val identifier: TextualInfo,
  val content: List<List<TaggedObjectInfo>>
) : AttributeInfo {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { attributeValue ->
      (attributeValue as DLSequence).map {
        (it as DLTaggedObject).let { outer ->
          TaggedObjectInfo(
            TaggedObjectMetaInfo(outer),
            (outer.baseObject as DLTaggedObject).let { inner ->
              TaggedObjectInfo(
                TaggedObjectMetaInfo(inner),
                TextualInfo.getInstance(inner.baseObject)
              )
            }
          )
        }
      }
    }
  )

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      content.map {
        it.toPrimitiveList().toDLSequence()
      }.toDLSet()
    ).toDLSequence()
}