package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.AttributeCertificate
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.SignerId
import org.bouncycastle.operator.DefaultAlgorithmNameFinder


fun ASN1Primitive.toEncodableInfo(): EncodableInfo = when (this) {

  is ASN1TaggedObject -> TaggedObjectInfo(
    TaggedObjectMetaInfo(this),
    this.baseObject.toASN1Primitive().toEncodableInfo()
  )

  is ASN1Sequence -> {
    try {
      SignerIdentifierInfo(
        SignerId(
          X500Name.getInstance(this.first()),
          (this.getObjectAt(1) as ASN1Integer).value
        )
      )
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      X500NameInfo(
        X500Name.getInstance(this)
      )
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      CounterSignatureInfo.getInstance(this as DLSequence)
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      if (DefaultAlgorithmNameFinder().getAlgorithmName(
          this.first() as ASN1ObjectIdentifier
        ) != this.first().toString()
      ) {
        AlgorithmInfo(
          AlgorithmIdentifier.getInstance(this)
        )
      } else {
        null
      }
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      AttributeInfo.getInstance(Attribute.getInstance(this))
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      EncapContentInfo.getInstance(ContentInfo.getInstance(this))
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      CertificateInfo.getInstance(
        X509CertificateHolder(
          Certificate.getInstance(
            this
          )
        )
      )
    } catch (_: Exception) {
      null
    }?.let { return it }

    try {
      CertificateInfo.getInstance(
        X509AttributeCertificateHolder(
          AttributeCertificate.getInstance(
            this
          )
        )
      )
    } catch (_: Exception) {
      null
    }?.let { return it }

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