package com.jetbrains.signatureverifier.tests.authenticode

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.DigestInfo

open class SpcIndirectDataContent(private val data: SpcAttributeOptional, private val messageDigest: DigestInfo) :
  ASN1Encodable {
  override fun toASN1Primitive(): ASN1Primitive {
    return BERSequence(getAsn1EncodableVectorInstance(data, messageDigest))
  }
}

open class SpcAttributeOptional(private val type: ASN1ObjectIdentifier, private val value: ASN1Encodable?) :
  ASN1Encodable {
  override fun toASN1Primitive(): ASN1Primitive {
    val v = getAsn1EncodableVectorInstance(type)
    if (value != null)
      v.add(value)
    return BERSequence(v)
  }
}

open class SpcPeImageData : ASN1Encodable {
  private val flags = DERBitString(ByteArray(0))
  private val file = SpcLink()

  override fun toASN1Primitive(): ASN1Primitive {
    return BERSequence(getAsn1EncodableVectorInstance(flags, DERTaggedObject(0, file)))
  }
}

open class SpcLink : ASN1Encodable, ASN1Choice {
  private val file = SpcString("")
  override fun toASN1Primitive(): ASN1Primitive {
    return DERTaggedObject(false, 2, file)
  }
}

open class SpcString(str: String) : ASN1Encodable, ASN1Choice {
  private val unicode = DERBMPString(str)

  override fun toASN1Primitive(): ASN1Primitive {
    return DERTaggedObject(false, 0, unicode)
  }
}

private fun getAsn1EncodableVectorInstance(vararg asn1Encodable: ASN1Encodable): ASN1EncodableVector {
  return ASN1EncodableVector().also { it.addAll(asn1Encodable) }
}
