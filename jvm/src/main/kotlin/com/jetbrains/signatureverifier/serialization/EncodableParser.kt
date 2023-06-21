package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x500.X500Name


fun ASN1Primitive.toEncodableInfo(): EncodableInfo = when (this) {
  is ASN1Sequence -> {
    try {
      X500NameInfo(X500Name.getInstance(this))
    } catch (_: IllegalArgumentException) {
      null
    }?.let { return it }
    SequenceInfo(this.map { it.toASN1Primitive().toEncodableInfo() })
  }

  is ASN1Set -> SetInfo(this.map { it.toASN1Primitive().toEncodableInfo() })

  is ASN1TaggedObject -> TaggedObjectInfo(
    TaggedObjectMetaInfo(this),
    this.baseObject.toASN1Primitive().toEncodableInfo()
  )

  else -> {
    try {
      val stringInfo = TextualInfo.getInstance(this)
      stringInfo
    } catch (_: IllegalArgumentException) {
      UnknownTypeInfo(this)
    }
  }
}