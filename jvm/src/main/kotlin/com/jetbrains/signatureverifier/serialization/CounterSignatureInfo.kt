package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.SignerId
import java.math.BigInteger

@Serializable
data class CounterSignatureInfo(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: AlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>,
  val digestEncryptionAlgorithm: AlgorithmInfo,
  val encryptedDigest: TextualInfo
) : EncodableInfo {

  companion object {
    fun getInstance(sequence: DLSequence): CounterSignatureInfo {
      val iterator = sequence.iterator()

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

      val encryptedDigest = TextualInfo.getInstance(iterator.next())

      return CounterSignatureInfo(
        version,
        signerIdentifierInfo,
        digestAlgorithm,
        attributes,
        encryptionAlgorithm,
        encryptedDigest
      )
    }
  }

  override fun toPrimitive(): ASN1Primitive =
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
}