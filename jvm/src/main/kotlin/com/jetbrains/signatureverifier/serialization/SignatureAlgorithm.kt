package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultAlgorithmNameFinder

// additionalValue is to be investigated, for now it is just null
data class SignatureAlgorithm(
  val name: String,
  val additionalValue: String? = null,
  val algorithmIdentifier: String
) {
  constructor(signatureAlgorithm: AlgorithmIdentifier) : this(
    DefaultAlgorithmNameFinder().getAlgorithmName(signatureAlgorithm.algorithm as ASN1ObjectIdentifier),
    if (signatureAlgorithm.parameters is ASN1Null) null else signatureAlgorithm.parameters
      .toString(),
    signatureAlgorithm.algorithm.toString()
  )

  fun toEncodableVector(): ASN1EncodableVector {
    val algorithm = ASN1EncodableVector()
    algorithm.add(ASN1ObjectIdentifier(algorithmIdentifier))
    algorithm.add(
      if (additionalValue != null) ASN1OctetString.getInstance(additionalValue)
      else DERNull.INSTANCE
    )
    return algorithm
  }
}