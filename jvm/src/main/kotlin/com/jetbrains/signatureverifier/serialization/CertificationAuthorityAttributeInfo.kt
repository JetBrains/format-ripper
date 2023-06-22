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

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { AlgorithmInfo(AlgorithmIdentifier.getInstance(it)) }
  )

  override fun toAttributeDLSequence(): DLSequence = listOf(
    identifier.toPrimitive(),
    content.toPrimitiveList().toDLSet()
  ).toDLSequence()
}