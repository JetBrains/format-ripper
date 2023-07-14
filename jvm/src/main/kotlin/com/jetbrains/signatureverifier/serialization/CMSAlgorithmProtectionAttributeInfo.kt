package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

@Serializable
data class CMSAlgorithmProtectionAttributeInfo(
  override val identifier: TextualInfo,
  val content: EncodableInfo
) : AttributeInfo() {

  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attrValues.toEncodableInfo()
  )

  override fun getPrimitiveContent() = content.toPrimitive()
}