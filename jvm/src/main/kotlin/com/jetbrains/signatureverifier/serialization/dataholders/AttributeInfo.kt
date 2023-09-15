package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.Attribute

@Serializable
sealed class AttributeInfo : EncodableInfo {
  companion object {
    fun getInstance(attribute: Attribute): AttributeInfo =
      when (attribute.attrType.id) {
        "1.2.840.113549.1.9.3" -> ContentTypeAttributeInfo(attribute)
        "1.2.840.113549.1.9.4" -> MessageDigestAttributeInfo(attribute)
        "1.3.6.1.4.1.311.2.1.11" -> MSCertExtensionsAttributeInfo(attribute)
        "1.3.6.1.4.1.311.2.1.12" -> MSCertificateTemplateV2AttributeInfo(attribute)
        "1.3.6.1.4.1.311.10.3.28" -> TimestampedDataAttributeInfo(attribute)
        "1.2.840.113549.1.9.5" -> SigningTimeAttributeInfo(attribute)
        "1.2.840.113635.100.9.2" -> CertificationAuthorityAttributeInfo(attribute)
        "1.2.840.113549.1.9.6" -> CounterSignatureAttributeInfo.getInstance(attribute)
        "1.2.840.113635.100.9.1" -> AppleDeveloperCertificateAttribute(attribute)
        "1.3.6.1.4.1.311.3.3.1" -> MsCounterSignAttributeInfo(attribute)
        "1.2.840.113549.1.9.52" -> CMSAlgorithmProtectionAttributeInfo(attribute)
        "1.2.840.113549.1.9.16.2.47" -> V2CertificateAttributeInfo(attribute)
        "1.2.840.113549.1.9.16.2.12" -> PublicKeyInfrastructureAttributeInfo(attribute)
        "1.2.840.113549.1.9.16.2.14" -> SignatureTimeStampAttributeInfo(attribute)
        "1.3.6.1.4.1.311.2.4.1" -> MSSpcNestedSignatureInfo(attribute)
        else -> UnknownAttributeInfo(attribute)
      }
  }

  abstract val identifier: TextualInfo

  abstract fun getPrimitiveContent(): ASN1Primitive

  override fun toPrimitive(): ASN1Primitive = listOf(
    identifier.toPrimitive(),
    getPrimitiveContent()
  ).toDLSequence()
    .toASN1Primitive()
}