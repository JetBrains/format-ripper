package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class CertificationAuthorityAttributeInfo(
  override val identifier: TextualInfo,
  val content: List<AlgorithmInfo>
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { AlgorithmInfo(AlgorithmIdentifier.getInstance(it)) }
  )

  override fun getPrimitiveContent() = content.toPrimitiveDLSet()
}