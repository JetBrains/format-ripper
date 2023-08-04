package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.OffsetDateTimeSerializer
import com.jetbrains.signatureverifier.serialization.toDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1UTCTime
import org.bouncycastle.asn1.cms.Attribute
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

@Serializable
class SigningTimeAttributeInfo(
  override val identifier: TextualInfo,
  val content: List<@Serializable(OffsetDateTimeSerializer::class) OffsetDateTime>
) : AttributeInfo() {
  constructor(attribute: Attribute) : this(
    TextualInfo.getInstance(attribute.attrType),
    attribute.attributeValues.map {
      OffsetDateTime.parse(
        it.toString(),
        dateTimeFormatter
      )
    }
  )

  companion object {
    val dateTimeFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmssX")
  }

  override fun getPrimitiveContent() = content.map {
    ASN1UTCTime(
      it.format(dateTimeFormatter)
    )
  }.toDLSet()
}