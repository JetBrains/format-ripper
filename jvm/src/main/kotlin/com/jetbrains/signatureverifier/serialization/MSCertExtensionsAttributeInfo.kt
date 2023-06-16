package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

// 1.3.6.1.4.1.311.2.1.11
@Serializable
data class MSCertExtensionsAttributeInfo(
  val identifier: StringInfo,
  val value: List<List<StringInfo>>
) : AttributeInfo() {
  override fun toAttributeDLSequence(): DLSequence = listToDLSequence(
    listOf(
      identifier.toPrimitive(),
      listToDLSet(
        value.map {
          listToDLSequence(
            it.map { s -> s.toPrimitive() }
          )
        }
      )
    )
  )

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map { (it as DLSequence).map { s -> StringInfo.getInstance(s) } }
  )
}