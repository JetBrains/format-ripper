package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.serialization.dataholders.*
import org.bouncycastle.asn1.*


fun ASN1Primitive.toEncodableInfo(): EncodableInfo = when (this) {

  is ASN1TaggedObject -> TaggedObjectInfo(
    isExplicit,
    tagNo,
    this.baseObject.toASN1Primitive().toEncodableInfo()
  )

  is ASN1Sequence -> {
    SequenceInfo(this.map { it.toASN1Primitive().toEncodableInfo() })
  }

  is ASN1Set -> SetInfo(this.map { it.toASN1Primitive().toEncodableInfo() })

  else -> {
    try {
      val stringInfo = TextualInfo.getInstance(this)
      stringInfo
    } catch (_: IllegalArgumentException) {
      UnknownTypeInfo(this)
    }
  }
}