package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultAlgorithmNameFinder

// additionalValue is to be investigated, for now it is just null
data class SignatureAlgorithmInfo(
  val name: String,
  val additionalValue: String? = null,
  val algorithmIdentifier: String
): EncodableInfo {
  constructor(signatureAlgorithm: AlgorithmIdentifier) : this(
    DefaultAlgorithmNameFinder().getAlgorithmName(signatureAlgorithm.algorithm as ASN1ObjectIdentifier),
    if (signatureAlgorithm.parameters is ASN1Null) null else signatureAlgorithm.parameters
      .toString(),
    signatureAlgorithm.algorithm.toString()
  )

  fun toDLSequence(): DLSequence {
    val algorithm = ASN1EncodableVector()
    algorithm.add(ASN1ObjectIdentifier(algorithmIdentifier))
    algorithm.add(
      if (additionalValue != null) ASN1OctetString.getInstance(additionalValue)
      else DERNull.INSTANCE
    )
    return DLSequence(algorithm)
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}