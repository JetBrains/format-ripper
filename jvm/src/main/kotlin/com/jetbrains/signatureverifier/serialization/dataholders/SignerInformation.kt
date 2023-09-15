package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cms.CMSProcessableByteArray
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation as BouncySignerInformation
import org.bouncycastle.asn1.cms.SignerInfo as BouncySignerInfo

@Serializable
data class SignerInformation(
  val signerInfo: SignerInfo,
  val contentType: TextualInfo,
  @Serializable(ByteArraySerializer::class)
  val content: ByteArray
) : EncodableInfo {

  private fun toBouncySignerInformation() = BouncySignerInformation(
    BouncySignerInfo.getInstance(signerInfo.toPrimitive()),
    ASN1ObjectIdentifier.getInstance(contentType.toPrimitive()),
    CMSProcessableByteArray(content),
    content
  )

  override fun toPrimitive(): ASN1Primitive =
    toBouncySignerInformation().toASN1Structure().toASN1Primitive()
}