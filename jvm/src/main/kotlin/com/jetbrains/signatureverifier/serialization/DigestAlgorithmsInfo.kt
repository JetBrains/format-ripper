package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

data class DigestAlgorithmsInfo(
  val content: List<AlgorithmInfo>
) : EncodableInfo {

  companion object {
    fun getInstance(algorithmsSet: Set<AlgorithmIdentifier>): DigestAlgorithmsInfo =
      DigestAlgorithmsInfo(
        algorithmsSet.map {
          AlgorithmInfo(it)
        }
      )
  }

  override fun toPrimitive(): ASN1Primitive = listToDLSet(content.map { it.toPrimitive() })

}