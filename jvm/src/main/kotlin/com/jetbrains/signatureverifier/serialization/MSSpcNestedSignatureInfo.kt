package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class MSSpcNestedSignatureInfo(
  override val identifier: TextualInfo,
  val content: List<RSASignedDataInfo>
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.map { RSASignedDataInfo.getInstance(it as DLSequence) }
  )

  override fun getPrimitiveContent() = content.toPrimitiveList().toDLSet()
}