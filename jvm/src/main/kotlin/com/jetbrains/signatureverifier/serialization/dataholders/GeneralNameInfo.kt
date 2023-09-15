package com.jetbrains.signatureverifier.serialization.dataholders

import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName

@Serializable
data class GeneralNameInfo(
  val name: X500NameInfo,
  val tag: Int
) : EncodableInfo {

  constructor(generalName: GeneralName) : this(
    X500NameInfo(generalName.name as X500Name),
    generalName.tagNo
  )

  override fun toPrimitive(): ASN1Primitive =
    TaggedObjectInfo.getTaggedObject(
      tag == 4,
      tag,
      name.toPrimitive()
    )
}