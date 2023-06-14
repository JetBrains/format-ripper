package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.DefaultAlgorithmNameFinder

data class DigestAlgorithmsInfo(
  val content: List<SignatureAlgorithmInfo>
) : EncodableInfo {

  companion object {
    fun getInstance(algorithmsSet: Set<AlgorithmIdentifier>): DigestAlgorithmsInfo =
      DigestAlgorithmsInfo(
        algorithmsSet.map {
          SignatureAlgorithmInfo(it)
        }
      )
  }

  override fun toPrimitive(): ASN1Primitive = listToDLSet(content.map { it.toPrimitive() })

}