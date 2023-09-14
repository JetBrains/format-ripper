package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.serialization.dataholders.*
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.SignerId
import org.bouncycastle.operator.DefaultAlgorithmNameFinder


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