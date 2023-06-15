package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
@Serializable
data class IssuerInfo(
  val name: String,
  val rdNs: List<List<rdNInfo>>
) : EncodableInfo {
  constructor(issuer: X500Name) : this(issuer.toString(),
    issuer.rdNs.map {
      it.typesAndValues.map { tv ->
        rdNInfo(
          StringInfo.getInstance(tv.type),
          StringInfo.getInstance(tv.value)
        )
      }
    })

  private fun toDLSequence(): DLSequence = listToDLSequence(
    rdNs.map {
      listToDLSet(it.map { info ->
        info.toPrimitive()
      })
    }
  )

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}