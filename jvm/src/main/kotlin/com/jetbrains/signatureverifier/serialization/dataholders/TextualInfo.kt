package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.BigIntegerSerializer
import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import com.jetbrains.signatureverifier.serialization.DateSerializer
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import java.math.BigInteger
import java.util.*

/**
 * Holds various Strings, Numeric and other formats, that can be converted to String and back
 */
@Serializable
sealed interface TextualInfo :
  EncodableInfo {

  companion object {
    fun getInstance(value: ASN1Encodable): TextualInfo =
      when (value) {
        is DERPrintableString -> DERPrintableStringInfo(value.toString())
        is DERUTF8String -> DERUTF8StringInfo(value.toString())
        is DERIA5String -> DERIA5StringInfo(value.toString())
        is DERBMPString -> DERBMPStringInfo(value.toString())
        is DERVisibleString -> DERVisibleStringInfo(value.toString())
        is DERUniversalString -> DERUniversalStringInfo(value.octets)
        is DERNumericString -> DERNumericStringInfo(value.toString())
        is DERGeneralString -> DERGeneralStringInfo(value.toString())
        is DEROctetString -> DEROctetStringInfo(value.octets)
        is ASN1ObjectIdentifier -> ASN1ObjectIdentifierInfo(value.toString())
        is DERBitString -> DERBitStringInfo(value.octets)
        is ASN1Boolean -> BooleanInfo(value.toString())
        is ASN1Integer -> IntegerInfo(value.toString())
        is ASN1UTCTime -> ASN1UTCTimeInfo(value.date)
        is ASN1GeneralizedTime -> ASN1GeneralizedTimeInfo(value.date)
        is ASN1Enumerated -> ASN1EnumeratedInfo(value.value)
        is ASN1Null -> ASN1NullInfo(value.toString())
        else -> throw IllegalArgumentException("This type of strings is not in list: ${value::class}")
      }

  }

  fun toEncodable(): ASN1Encodable

  override fun toPrimitive(): ASN1Primitive = toEncodable().toASN1Primitive()
}

@Serializable
sealed class DateTextualInfo : TextualInfo {

  @Serializable(DateSerializer::class)
  abstract val content: Date
}

@Serializable
data class ASN1UTCTimeInfo(
  override val content: @Serializable(DateSerializer::class) Date
) : DateTextualInfo() {
  override fun toEncodable(): ASN1Encodable = ASN1UTCTime(content)
}

@Serializable
data class ASN1GeneralizedTimeInfo(
  override val content: @Serializable(DateSerializer::class) Date
) :
  DateTextualInfo() {
  override fun toEncodable(): ASN1Encodable = ASN1GeneralizedTime(content)
}

@Serializable
sealed class HexTextualInfo : TextualInfo {
  @Serializable(ByteArraySerializer::class)
  abstract val content: ByteArray
}

@Serializable
data class ASN1EnumeratedInfo(
  val content: @Serializable(BigIntegerSerializer::class) BigInteger
) : TextualInfo {
  override fun toEncodable(): ASN1Encodable = ASN1Enumerated(content)
}

@Serializable
data class DERUniversalStringInfo(
  @Serializable(ByteArraySerializer::class)
  override val content: ByteArray
) : HexTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERUniversalString(content)
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as DERUniversalStringInfo

    return content.contentEquals(other.content)
  }

  override fun hashCode(): Int {
    return content.contentHashCode()
  }
}

@Serializable
data class DEROctetStringInfo(
  @Serializable(ByteArraySerializer::class)
  override val content: ByteArray
) : HexTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DEROctetString(content)
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as DEROctetStringInfo

    return content.contentEquals(other.content)
  }

  override fun hashCode(): Int {
    return content.contentHashCode()
  }
}

@Serializable
data class DERBitStringInfo(
  @Serializable(ByteArraySerializer::class)
  override val content: ByteArray
) : HexTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERBitString(content)
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as DERBitStringInfo

    return content.contentEquals(other.content)
  }

  override fun hashCode(): Int {
    return content.contentHashCode()
  }
}

@Serializable
sealed class StringTextualInfo : TextualInfo {
  abstract val content: String
}

@Serializable
data class DERPrintableStringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERPrintableString(content)
}

@Serializable
data class DERUTF8StringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERUTF8String(content)
}

@Serializable
data class DERIA5StringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERIA5String(content)
}

@Serializable
data class DERBMPStringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERBMPString(content)
}

@Serializable
data class DERVisibleStringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERVisibleString(content)
}

@Serializable
data class DERNumericStringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERNumericString(content)
}

@Serializable
data class DERGeneralStringInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERGeneralString(content)
}

@Serializable
data class ASN1ObjectIdentifierInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = ASN1ObjectIdentifier(content)
}

@Serializable
data class BooleanInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = ASN1Boolean.getInstance(if (content == "TRUE") 1 else 0)
}

@Serializable
data class IntegerInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = ASN1Integer(content.toBigInteger())
}

@Serializable
data class ASN1NullInfo(override val content: String) : StringTextualInfo() {
  override fun toEncodable(): ASN1Encodable = DERNull.INSTANCE
}
