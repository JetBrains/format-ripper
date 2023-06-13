package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name

data class IssuerInfo(
  val name: String,
  val rdNs: List<List<rdNInfo>>
) : EncodableInfo {
  constructor(issuer: X500Name) : this(issuer.toString(),
    issuer.rdNs.map {
      it.typesAndValues.map { tv ->
        rdNInfo(
          tv.type.toString(),
          StringInfo.getInstance(tv.value)
        )
      }
    })

  fun toDLSequence(): DLSequence {
    val outerVector = ASN1EncodableVector()

    val mapped = rdNs.map {
      val innerVector = ASN1EncodableVector()
      innerVector.addAll(
        it.map { info ->
          info.toPrimitive()
        }.toTypedArray()
      )
      DLSet(innerVector)
    }

    outerVector.addAll(mapped.toTypedArray())
    return DLSequence(outerVector)
  }

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}