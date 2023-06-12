package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString

data class ExtensionInfo(
  val key: String,
  val critical: Boolean,
  val value: ByteArray
) {
  fun toEncodableVector(): ASN1EncodableVector {
    val vector = ASN1EncodableVector()
    vector.add(ASN1ObjectIdentifier(key))
    if (critical) {
      vector.add(ASN1Boolean.TRUE)
    }
    vector.add(DEROctetString(value))

    return vector
  }
}