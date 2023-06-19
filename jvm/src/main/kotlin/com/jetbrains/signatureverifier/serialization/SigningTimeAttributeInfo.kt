package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1UTCTime
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

@Serializable
class SigningTimeAttributeInfo(
  val identifier: StringInfo,
  @Serializable(OffsetDateTimeSerializer::class)
  val content: OffsetDateTime
) : AttributeInfo {

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
        listOf(
          ASN1UTCTime(content.format(DateTimeFormatter.ofPattern("yyMMddHHmmssX")))
        ).toDLSet()
    ).toDLSequence()

  constructor(attribute: Attribute) : this(
    StringInfo.getInstance(attribute.attrType),
    OffsetDateTime.parse(
      attribute.attributeValues.first().toString(),
      DateTimeFormatter.ofPattern("yyMMddHHmmssX")
    )
  )
}