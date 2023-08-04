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
//    trySignerIdentifierInfo(this)?.let { return it }

    tryX500NameInfo(this)?.let { return it }

//    tryCounterSignatureInfo(this)?.let { return it }

    tryAlgorithmInfo(this)?.let { return it }

//    tryAttributeInfo(this)?.let { return it }

//    tryEncapContentInfo(this)?.let { return it }

//    tryCertificateInfo(this)?.let { return it }

//    tryCertificateInfo(this)?.let { return it }

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

private fun tryCertificateInfo(sequence: ASN1Sequence) = try {
  CertificateInfo.getInstance(
    X509CertificateHolder(
      Certificate.getInstance(
        sequence
      )
    )
  )
} catch (_: Exception) {
  null
}

private fun tryEncapContentInfo(sequence: ASN1Sequence) = try {
  EncapContentInfo.getInstance(ContentInfo.getInstance(sequence))
} catch (_: Exception) {
  null
}

private fun tryAttributeInfo(sequence: ASN1Sequence) = try {
  AttributeInfo.getInstance(Attribute.getInstance(sequence))
} catch (_: Exception) {
  null
}

private fun tryAlgorithmInfo(sequence: ASN1Sequence) = try {
  if (DefaultAlgorithmNameFinder().getAlgorithmName(
      sequence.first() as ASN1ObjectIdentifier
    ) != sequence.first().toString()
  ) {
    AlgorithmInfo(
      AlgorithmIdentifier.getInstance(sequence)
    )
  } else {
    null
  }
} catch (_: Exception) {
  null
}

private fun tryCounterSignatureInfo(sequence: ASN1Sequence) = try {
  CounterSignatureInfo.getInstance(sequence as DLSequence)
} catch (_: Exception) {
  null
}

private fun tryX500NameInfo(sequence: ASN1Sequence) = try {
  X500NameInfo(
    X500Name.getInstance(sequence)
  )
} catch (_: Exception) {
  null
}

private fun trySignerIdentifierInfo(sequence: ASN1Sequence) = try {
  SignerIdentifierInfo(
    SignerId(
      X500Name.getInstance(sequence.first()),
      (sequence.getObjectAt(1) as ASN1Integer).value
    )
  )
} catch (_: Exception) {
  null
}