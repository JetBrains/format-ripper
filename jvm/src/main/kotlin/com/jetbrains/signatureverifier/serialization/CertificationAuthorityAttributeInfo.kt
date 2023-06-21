package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class CertificationAuthorityAttributeInfo(
  val identifier: TextualInfo,
  val content: List<AlgorithmInfo>
) : AttributeInfo {
  override fun toAttributeDLSequence(): DLSequence = listOf(
    identifier.toPrimitive(),
    content.map { it.toPrimitive() }.toDLSet()
  ).toDLSequence()

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { AlgorithmInfo(AlgorithmIdentifier.getInstance(it)) }
  )
}