package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultAlgorithmNameFinder

// additionalValue is to be investigated, for now it is just null
data class SignatureAlgorithmInfo(
  val name: String,
  val additionalValue: StringInfo? = null,
  val algorithmIdentifier: StringInfo
) : EncodableInfo {
  constructor(signatureAlgorithm: AlgorithmIdentifier) : this(
    DefaultAlgorithmNameFinder().getAlgorithmName(signatureAlgorithm.algorithm as ASN1ObjectIdentifier),
    if (signatureAlgorithm.parameters == null) null else StringInfo.getInstance(
      signatureAlgorithm.parameters
    ),
    StringInfo.getInstance(signatureAlgorithm.algorithm)
  )

  private fun toDLSequence(): DLSequence {
    val list = mutableListOf(algorithmIdentifier.toPrimitive())
    if (additionalValue != null) {
      list.add(additionalValue.toPrimitive())
    }
    return listToDLSequence(list)
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}