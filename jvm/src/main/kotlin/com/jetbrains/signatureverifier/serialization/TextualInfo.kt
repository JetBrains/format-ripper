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

    private val asnToString = mapOf<Class<out ASN1Primitive>, Pair<String, (ASN1Primitive) -> String>>(
      Pair(
        org.bouncycastle.asn1.DERBitString::class.java,
        Pair("BitString") { x -> (x as DERBitString).octets.toHexString() }),
      Pair(
        org.bouncycastle.asn1.ASN1Enumerated::class.java,
        Pair("Enumerated") { x -> (x as ASN1Enumerated).value.toString() }),
      Pair(
        org.bouncycastle.asn1.ASN1Integer::class.java,
        Pair("Integer") { x -> (x as ASN1Integer).value.toString() }),
      Pair(
        org.bouncycastle.asn1.ASN1ObjectIdentifier::class.java,
        Pair("ObjectIdentifier") { x -> (x as ASN1ObjectIdentifier).toString() }),
      Pair(
        org.bouncycastle.asn1.DERGeneralString::class.java,
        Pair("GeneralString") { x -> (x as DERGeneralString).toString() }),
      Pair(
        org.bouncycastle.asn1.DERNumericString::class.java,
        Pair("NumericString") { x -> (x as DERNumericString).toString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERVisibleString::class.java,
        Pair("VisibleString") { x -> (x as DERVisibleString).toString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERT61String::class.java,
        Pair("T61String") { x -> (x as DERT61String).toString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERBMPString::class.java,
        Pair("BmpString") { x -> (x as DERBMPString).toString() }),
      Pair(
        org.bouncycastle.asn1.DERIA5String::class.java,
        Pair("IA5String") { x -> (x as DERIA5String).toString() }),
      Pair(
        org.bouncycastle.asn1.DERUTF8String::class.java,
        Pair("Utf8String") { x -> (x as DERUTF8String).toString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERPrintableString::class.java,
        Pair("PrintableString") { x -> (x as DERPrintableString).toString() }
      ),
      Pair(
        org.bouncycastle.asn1.DEROctetString::class.java,
        Pair("OctetString") { x -> (x as DEROctetString).octets.toHexString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERVideotexString::class.java,
        Pair("VideotexString") { x -> (x as DERVideotexString).octets.toHexString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERUniversalString::class.java,
        Pair("UniversalString") { x -> (x as DERUniversalString).octets.toHexString() }
      ),
      Pair(
        org.bouncycastle.asn1.DERGraphicString::class.java,
        Pair("GraphicString") { x -> (x as DERGraphicString).octets.toHexString() }
      ),
      Pair(
        org.bouncycastle.asn1.ASN1GeneralizedTime::class.java,
        Pair("GeneralizedTime") { x -> dateFormat.format((x as ASN1GeneralizedTime).date) }
      ),
      Pair(
        org.bouncycastle.asn1.ASN1UTCTime::class.java,
        Pair("UtcTime") { x -> dateFormat.format((x as ASN1UTCTime).adjustedDate) }),
      Pair(org.bouncycastle.asn1.DERNull::class.java, Pair("Null") { _ -> "NULL" })
    )

    private val fromStringMethods = mapOf<String, (String) -> ASN1Primitive>(
      "BitString" to { str -> DERBitString(str.toByteArray()) },
      "Enumerated" to { str -> ASN1Enumerated(BigInteger(str)) },
      "Integer" to { str -> ASN1Integer(BigInteger(str)) },
      "ObjectIdentifier" to { str -> ASN1ObjectIdentifier(str) },
      "GeneralString" to { str -> DERGeneralString(str) },
      "NumericString" to { str -> DERNumericString(str) },
      "VisibleString" to { str -> DERVisibleString(str) },
      "T61String" to { str -> DERT61String(str) },
      "BmpString" to { str -> DERBMPString(str) },
      "IA5String" to { str -> DERIA5String(str) },
      "Utf8String" to { str -> DERUTF8String(str) },
      "PrintableString" to { str -> DERPrintableString(str) },
      "OctetString" to { str -> DEROctetString(str.toByteArray()) },
      "VideotexString" to { str -> DERVideotexString(str.toByteArray()) },
      "UniversalString" to { str -> DERUniversalString(str.toByteArray()) },
      "GraphicString" to { str -> DERGraphicString(str.toByteArray()) },
      "GeneralizedTime" to { str -> DERGeneralizedTime(dateFormat.parse(str)) },
      "UtcTime" to { str -> DERUTCTime(dateFormat.parse(str)) },
      "Null" to { _ -> DERNull.INSTANCE }
    )

    fun getType(value: ASN1Primitive): String {
      return asnToString[value.javaClass]?.first
        ?: throw IllegalArgumentException("Unknown ASN type ${value.javaClass}")
    }

    fun getStringValue(value: ASN1Primitive): String {
      return asnToString[value.javaClass]?.second?.invoke(value)
        ?: throw IllegalArgumentException("Unknown ASN type ${value.javaClass}")
    }

    fun getPrimitive(type: String, value: String): ASN1Primitive {
      return fromStringMethods[type]?.invoke(value) ?: throw IllegalArgumentException("Unknown type $type")
    }
  }
}