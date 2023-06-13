package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.ASN1Primitive

interface EncodableInfo {
  fun toPrimitive(): ASN1Primitive
}