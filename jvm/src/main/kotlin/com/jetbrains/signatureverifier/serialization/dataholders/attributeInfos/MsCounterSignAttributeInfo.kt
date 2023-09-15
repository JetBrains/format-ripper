package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toDLSet
import com.jetbrains.signatureverifier.serialization.toPrimitiveList
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class MsCounterSignAttributeInfo(
  override val identifier: TextualInfo,
  val contentIdentifier: List<TextualInfo>,
  val content: List<TaggedObjectInfo>
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map {
      TextualInfo.getInstance((it as DLSequence).first())
    },
    attribute.attributeValues.map {
      (it as DLSequence).last().let { sequence ->
        TaggedObjectInfo(
          (sequence as DLTaggedObject).isExplicit,
          sequence.tagNo,
          MsCounterSignatureInfo.getInstance(sequence.baseObject as DLSequence)
        )
      }
    }
  )

  override fun getPrimitiveContent() = contentIdentifier.toPrimitiveList().zip(content.toPrimitiveList()).map {
    it.toList().toDLSequence()
  }.toDLSet()
}