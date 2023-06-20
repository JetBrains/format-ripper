package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.util.encoders.Hex

@Serializable
data class StringInfo(val stringType: StringType, val content: String) : EncodableInfo {
  companion object {
    // This is not exhaustive and may shoot you in the leg some day
    enum class StringType(val stringClass: Class<out Any>) {
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
      X500Name(org.bouncycastle.asn1.x500.X500Name::class.java)
    }

    fun getStringType(value: ASN1Encodable) =
      when (value) {
        is DERPrintableString -> StringType.DERPrintableString
        is DERUTF8String -> StringType.DERUTF8String
        is DERIA5String -> StringType.DERIA5String
        is DERBMPString -> StringType.DERBMPString
        is DERVisibleString -> StringType.DERVisibleString
        is DERUniversalString -> StringType.DERUniversalString
        is DERNumericString -> StringType.DERNumericString
        is DERGeneralString -> StringType.DERGeneralString
        is DEROctetString -> StringType.DEROctetString
        is ASN1ObjectIdentifier -> StringType.ASN1ObjectIdentifier
        is DERBitString -> StringType.DERBitString
        // Technically not a string, but we need it for consistency
        is ASN1Null -> StringType.ASN1Null
        is ASN1Integer -> StringType.Integer
        else -> throw IllegalArgumentException("This type of strings is not in list: ${value::class}")
      }

    fun getInstance(value: ASN1Encodable): StringInfo {
      val type = getStringType(value)
      val content = when (type) {
        StringType.DERBitString -> Hex.toHexString((value as DERBitString).octets)
        StringType.DEROctetString -> Hex.toHexString((value as DEROctetString).octets)
        else -> value.toString()
      }
      return StringInfo(type, content)
    }

  }

  private fun toEncodableString(): ASN1Encodable {
    val stringClass = stringType.stringClass

    return when (stringType) {
      StringType.DERBitString,
      StringType.DEROctetString -> {
        val constructor = stringClass.getConstructor(ByteArray::class.java)
        constructor.newInstance(Hex.decode(content)) as ASN1Encodable
      }

      StringType.ASN1Null -> DERNull.INSTANCE

      StringType.Integer -> ASN1Integer(content.toBigInteger())

      else -> {
        val constructor = stringClass.getConstructor(String::class.java)
        constructor.newInstance(content) as ASN1Encodable
      }

    }
  }

  override fun toPrimitive(): ASN1Primitive = toEncodableString().toASN1Primitive()
}