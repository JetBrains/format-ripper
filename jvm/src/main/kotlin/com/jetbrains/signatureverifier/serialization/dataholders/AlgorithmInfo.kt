package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toEncodableInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultAlgorithmNameFinder

@Serializable
data class AlgorithmInfo(
  val name: String,
  val additionalValue: EncodableInfo? = null,
  val algorithmIdentifier: TextualInfo
) : EncodableInfo {
  constructor(signatureAlgorithm: AlgorithmIdentifier) : this(
    DefaultAlgorithmNameFinder().getAlgorithmName(
      signatureAlgorithm.algorithm as ASN1ObjectIdentifier
    ),
    signatureAlgorithm.parameters?.toASN1Primitive()?.toEncodableInfo(),
    TextualInfo.getInstance(signatureAlgorithm.algorithm)
  )

  private fun toDLSequence(): DLSequence {
    val list = mutableListOf(algorithmIdentifier.toPrimitive())
    if (additionalValue != null) {
      list.add(additionalValue.toPrimitive())
    }
    return list.toDLSequence()
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}