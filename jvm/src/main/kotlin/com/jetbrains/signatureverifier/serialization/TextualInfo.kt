package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.util.encoders.Hex
import java.text.DateFormat
import java.text.SimpleDateFormat

/**
 * Holds various Strings, Numeric and other formats, that can be converted to String and back
 */
@Serializable
data class TextualInfo(val contentType: ContentType, val content: String) :
  EncodableInfo {
  companion object {
    val dateFormat: DateFormat = SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS")

    enum class ContentType(val contentClass: Class<out Any>) {
      DERPrintableString(org.bouncycastle.asn1.DERPrintableString::class.java),
      DERUTF8String(org.bouncycastle.asn1.DERUTF8String::class.java),
      DERIA5String(org.bouncycastle.asn1.DERIA5String::class.java),
      DERBMPString(org.bouncycastle.asn1.DERBMPString::class.java),
      DERVisibleString(org.bouncycastle.asn1.DERVisibleString::class.java),
      DERUniversalString(org.bouncycastle.asn1.DERUniversalString::class.java),
      DERNumericString(org.bouncycastle.asn1.DERNumericString::class.java),
      DERGeneralString(org.bouncycastle.asn1.DERGeneralString::class.java),
      DEROctetString(org.bouncycastle.asn1.DEROctetString::class.java),
      ASN1ObjectIdentifier(org.bouncycastle.asn1.ASN1ObjectIdentifier::class.java),
      DERBitString(org.bouncycastle.asn1.DERBitString::class.java),
      ASN1Null(org.bouncycastle.asn1.ASN1Null::class.java),
      Integer(org.bouncycastle.asn1.ASN1Integer::class.java),
      Boolean(org.bouncycastle.asn1.ASN1Boolean::class.java),
      ASN1UTCTime(org.bouncycastle.asn1.ASN1UTCTime::class.java),
      ASN1GeneralizedTime(org.bouncycastle.asn1.ASN1GeneralizedTime::class.java),
      ASN1Enumerated(org.bouncycastle.asn1.ASN1Enumerated::class.java)
    }

    private fun getStringType(value: ASN1Encodable) =
      when (value) {
        is DERPrintableString -> ContentType.DERPrintableString
        is DERUTF8String -> ContentType.DERUTF8String
        is DERIA5String -> ContentType.DERIA5String
        is DERBMPString -> ContentType.DERBMPString
        is DERVisibleString -> ContentType.DERVisibleString
        is DERUniversalString -> ContentType.DERUniversalString
        is DERNumericString -> ContentType.DERNumericString
        is DERGeneralString -> ContentType.DERGeneralString
        is DEROctetString -> ContentType.DEROctetString
        is ASN1ObjectIdentifier -> ContentType.ASN1ObjectIdentifier
        is DERBitString -> ContentType.DERBitString
        is ASN1Boolean -> ContentType.Boolean
        is ASN1Integer -> ContentType.Integer
        is ASN1UTCTime -> ContentType.ASN1UTCTime
        is ASN1GeneralizedTime -> ContentType.ASN1GeneralizedTime
        is ASN1Enumerated -> ContentType.ASN1Enumerated
        is ASN1Null -> ContentType.ASN1Null
        else -> throw IllegalArgumentException("This type of strings is not in list: ${value::class}")
      }

    fun getInstance(value: ASN1Encodable): TextualInfo {
      val type = getStringType(value)
      val content = when (type) {
        ContentType.DERBitString -> Hex.toHexString((value as DERBitString).octets)
        ContentType.DEROctetString -> Hex.toHexString((value as DEROctetString).octets)

        ContentType.ASN1UTCTime ->
          dateFormat.format((value as ASN1UTCTime).date)

        ContentType.ASN1GeneralizedTime ->
          dateFormat.format((value as ASN1GeneralizedTime).date)

        ContentType.ASN1Enumerated -> (value as ASN1Enumerated).value.toString()

        else -> value.toString()
      }
      return TextualInfo(type, content)
    }

  }

  private fun toEncodable(): ASN1Encodable {
    val contentClass = contentType.contentClass

    return when (contentType) {
      ContentType.DERBitString,
      ContentType.DEROctetString -> {
        val constructor = contentClass.getConstructor(ByteArray::class.java)
        constructor.newInstance(Hex.decode(content)) as ASN1Encodable
      }

      ContentType.ASN1Null -> DERNull.INSTANCE
      ContentType.Integer -> ASN1Integer(content.toBigInteger())
      ContentType.Boolean -> ASN1Boolean.getInstance(if (content == "TRUE") 1 else 0)
      ContentType.ASN1GeneralizedTime -> ASN1GeneralizedTime(dateFormat.parse(content))
      ContentType.ASN1UTCTime -> ASN1UTCTime(dateFormat.parse(content))
      ContentType.ASN1Enumerated -> ASN1Enumerated(content.toBigInteger())

      else -> {
        val constructor = contentClass.getConstructor(String::class.java)
        constructor.newInstance(content) as ASN1Encodable
      }

    }
  }

  override fun toPrimitive(): ASN1Primitive = toEncodable().toASN1Primitive()
}