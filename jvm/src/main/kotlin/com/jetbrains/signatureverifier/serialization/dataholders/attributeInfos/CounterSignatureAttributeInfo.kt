package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class CounterSignatureAttributeInfo(
  override val identifier: TextualInfo,
  val content: List<CounterSignatureInfo>
) : AttributeInfo() {

  companion object {
    fun getInstance(attribute: Attribute): CounterSignatureAttributeInfo {
      return CounterSignatureAttributeInfo(
        TextualInfo.getInstance(attribute.attrType),
        attribute.attributeValues.map { CounterSignatureInfo.getInstance(it as DLSequence) }
      )
    }
  }

  override fun getPrimitiveContent() = content.toPrimitiveDLSet()
}