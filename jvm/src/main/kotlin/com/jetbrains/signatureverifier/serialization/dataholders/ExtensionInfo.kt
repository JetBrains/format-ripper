package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
@Serializable
data class ExtensionInfo(
  val key: TextualInfo,
  val critical: Boolean,
  val value: TextualInfo
) : EncodableInfo {
  private fun toDLSequence(): DLSequence = listOf(
    key.toPrimitive(),
    (if (critical) ASN1Boolean.TRUE else null),
    value.toPrimitive()
  ).toDLSequence()

  override fun toPrimitive(): ASN1Primitive = toDLSequence().toASN1Primitive()
}