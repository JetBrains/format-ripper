package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name

data class IssuerInfo(
  val name: String,
  val rdNs: List<List<rdNInfo>>
) {
  constructor(issuer: X500Name) : this(issuer.toString(),
    issuer.rdNs.map {
      it.typesAndValues.map { tv ->
        rdNInfo(
          tv.type.toString(),
          DerStringInfo(tv.value)
        )
      }
    })

  fun toEncodableVector(): ASN1EncodableVector {
    val outerVector = ASN1EncodableVector()

    val mapped = rdNs.map {
      val innerVector = ASN1EncodableVector()
      innerVector.addAll(
        it.map { info ->
          val sequense = ASN1EncodableVector()

          val string = info.value.toEncodableString()


          sequense.addAll(
            listOf(
              ASN1ObjectIdentifier(info.type),
              string
            ).toTypedArray()
          )
          DLSequence(sequense)
        }.toTypedArray()
      )
      DLSet(innerVector)
    }

    outerVector.addAll(mapped.toTypedArray())
    return outerVector
  }
}