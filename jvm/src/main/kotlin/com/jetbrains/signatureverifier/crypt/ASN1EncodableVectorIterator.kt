package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector

class ASN1EncodableVectorIterator(private val encodableVector: ASN1EncodableVector) : Iterator<ASN1Encodable> {
  private var idx = 0
  private val size = encodableVector.size()

  override fun hasNext(): Boolean {
    return idx < size
  }

  override fun next(): ASN1Encodable {
    val res = encodableVector[idx]
    idx++
    return res
  }
}