package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import java.lang.IllegalArgumentException

data class DerStringInfo(val stringType: StringType, val content: String) {
  companion object{
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
      DERGraphicString(org.bouncycastle.asn1.DERGraphicString::class.java),
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
        is DERGraphicString -> StringType.DERGraphicString
        else -> throw IllegalArgumentException("This type of strings is not in list")
      }
  }
  constructor(value: ASN1Encodable) : this(getStringType(value), value.toString())

  fun toEncodableString(): ASN1Encodable{
    val stringClass = stringType.stringClass
    val constructor = stringClass.getConstructor(String::class.java)
    return constructor.newInstance(content) as ASN1Encodable
  }
}