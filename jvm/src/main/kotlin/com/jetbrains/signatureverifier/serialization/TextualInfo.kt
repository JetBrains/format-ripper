package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import java.math.BigInteger
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.*

abstract class TextualInfo {
  companion object {
    private val dateFormat: DateFormat =
      SimpleDateFormat("dd.MM.yyy HH:mm:ss").apply { timeZone = TimeZone.getTimeZone("UTC") }

    fun getTaggedValue(value: ASN1Primitive): String =
      when (value) {
        is DERBitString -> "[BitString] ${value.octets.toHexString()}"
        is ASN1Enumerated -> "[Enumerated] ${value.value}"
        is ASN1Integer -> "[Integer] ${value.value}"
        is ASN1ObjectIdentifier -> "[ObjectIdentifier] $value"
        is DERGeneralString -> "[GeneralString] $value"
        is DERNumericString -> "[NumericString] $value"
        is DERVisibleString -> "[VisibleString] $value"
        is DERT61String -> "[T61String] $value"
        is DERBMPString -> "[BmpString] $value"
        is DERIA5String -> "[IA5String] $value"
        is DERUTF8String -> "[Utf8String] $value"
        is DERPrintableString -> "[PrintableString] $value"
        is DEROctetString -> "[OctetString] ${value.octets.toHexString()}"
        is DERVideotexString -> "[VideotexString] ${value.octets.toHexString()}"
        is DERUniversalString -> "[UniversalString] ${value.octets.toHexString()}"
        is DERGraphicString -> "[GraphicString] ${value.octets.toHexString()}"
        is ASN1GeneralizedTime -> "[GeneralizedTime] ${dateFormat.format(value.date)}"
        is ASN1UTCTime -> "[UtcTime] ${dateFormat.format(value.adjustedDate)}"
        is DERNull -> "[Null] NULL"
        else -> throw IllegalArgumentException("Unknown ASN type: ${value.javaClass}")
      }

    fun getPrimitive(type: String, value: String): ASN1Primitive = when (type) {
      "BitString" -> DERBitString(value.toByteArray())
      "Enumerated" -> ASN1Enumerated(BigInteger(value))
      "Integer" -> ASN1Integer(BigInteger(value))
      "ObjectIdentifier" -> ASN1ObjectIdentifier(value)
      "GeneralString" -> DERGeneralString(value)
      "NumericString" -> DERNumericString(value)
      "VisibleString" -> DERVisibleString(value)
      "T61String" -> DERT61String(value)
      "BmpString" -> DERBMPString(value)
      "IA5String" -> DERIA5String(value)
      "Utf8String" -> DERUTF8String(value)
      "PrintableString" -> DERPrintableString(value)
      "OctetString" -> DEROctetString(value.toByteArray())
      "VideotexString" -> DERVideotexString(value.toByteArray())
      "UniversalString" -> DERUniversalString(value.toByteArray())
      "GraphicString" -> DERGraphicString(value.toByteArray())
      "GeneralizedTime" -> DERGeneralizedTime(dateFormat.parse(value))
      "UtcTime" -> DERUTCTime(dateFormat.parse(value))
      "Null" -> DERNull.INSTANCE
      else -> throw IllegalArgumentException("Unknown type $type")
    }
  }
}