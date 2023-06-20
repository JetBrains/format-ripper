package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class CounterSignatureAttributeInfo(
  val identifier: StringInfo,
  val content: List<CounterSignatureInfo>
) : AttributeInfo {

  companion object {
    fun getInstance(attribute: Attribute): CounterSignatureAttributeInfo {
      return CounterSignatureAttributeInfo(
        StringInfo.getInstance(attribute.attrType),
        attribute.attributeValues.map { CounterSignatureInfo.getInstance(it as DLSequence) }
      )
    }
  }

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      content.map { it.toPrimitive() }.toDLSet()
    ).toDLSequence()
}