package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.SignerId
import java.math.BigInteger

@Serializable
data class CounterSignatureAttributeInfo(
  val identifier: StringInfo,
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: AlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>,
  val digestEncryptionAlgorithm: AlgorithmInfo,
  val encryptedDigest: StringInfo
) : AttributeInfo {

  companion object {
    fun getInstance(attribute: Attribute): CounterSignatureAttributeInfo {
      val iterator = (attribute.attributeValues.first() as DLSequence).iterator()

      val version = (iterator.next() as ASN1Integer).intValueExact()
      val signerSequence = (iterator.next() as DLSequence).toList()
      val signerIdentifierInfo = SignerIdentifierInfo(
        SignerId(
          X500Name.getInstance(
            signerSequence[0]
          ),
          BigInteger(
            (signerSequence[1] as ASN1Integer).toString()
          )
        )
      )
      val digestAlgorithm = AlgorithmInfo(
        AlgorithmIdentifier.getInstance(iterator.next())
      )

      val attributes = ((iterator.next() as DLTaggedObject).baseObject as DLSequence).map {
        AttributeInfo.getInstance(Attribute.getInstance(it))
      }

      val encryptionAlgorithm = AlgorithmInfo(
        AlgorithmIdentifier.getInstance(iterator.next())
      )

      val encryptedDigest = StringInfo.getInstance(iterator.next())

      return CounterSignatureAttributeInfo(
        StringInfo.getInstance(attribute.attrType),
        version,
        signerIdentifierInfo,
        digestAlgorithm,
        attributes,
        encryptionAlgorithm,
        encryptedDigest
      )
    }
  }

  override fun toAttributeDLSequence(): DLSequence =
    listOf(
      identifier.toPrimitive(),
      listOf(
        listOf(
          ASN1Integer(version.toLong()),
          sid.toPrimitive(),
          digestAlgorithm.toPrimitive(),
          TaggedObjectInfo.getTaggedObjectWithMetaInfo(
            TaggedObjectMetaInfo(0, 4),
            authenticatedAttributes.map { it.toPrimitive() }.toDLSet()
          ),
          digestEncryptionAlgorithm.toPrimitive(),
          encryptedDigest.toPrimitive(),
        ).toDLSequence()
      ).toDLSet()
    ).toDLSequence()
}