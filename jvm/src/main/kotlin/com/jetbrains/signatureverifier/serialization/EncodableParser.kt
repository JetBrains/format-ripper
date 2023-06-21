package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject


fun ASN1Primitive.toEncodableInfo(): EncodableInfo = when (this) {
  is ASN1Sequence -> SequenceInfo(this.map { it.toASN1Primitive().toEncodableInfo() })

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