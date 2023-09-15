package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation
import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSet
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class SignerInfo(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: AlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>,
  val digestEncryptionAlgorithm: AlgorithmInfo,
  val encryptedDigest: TextualInfo,
  val unauthenticatedAttributes: List<AttributeInfo>?
) : EncodableInfo {

  constructor(signer: SignerInformation) : this(
    signer.version,
    SignerIdentifierInfo(signer.sID),
    AlgorithmInfo(signer.digestAlgorithmID),
    signer.toASN1Structure().authenticatedAttributes.map {
      AttributeInfo.getInstance(
        signer.signedAttributes?.get(
          (it as DLSequence).first() as ASN1ObjectIdentifier
        ) as Attribute
      )
    },
    AlgorithmInfo(signer.encryptionAlgorithm),
    TextualInfo.getInstance(signer.toASN1Structure().encryptedDigest),
    signer.toASN1Structure().unauthenticatedAttributes?.map {
      AttributeInfo.getInstance(
        signer.unsignedAttributes?.get(
          (it as DLSequence).first() as ASN1ObjectIdentifier
        ) as Attribute
      )
    }
  )

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      ASN1Integer(version.toLong()),
      sid.toPrimitive(),
      digestAlgorithm.toPrimitive(),
      TaggedObjectInfo.getTaggedObject(
        false,
        0,
        authenticatedAttributes.toPrimitiveDLSet()
      ),
      digestEncryptionAlgorithm.toPrimitive(),
      encryptedDigest.toPrimitive(),
      unauthenticatedAttributes?.let { attributes ->
        TaggedObjectInfo.getTaggedObject(
          false,
          1,
          attributes.toPrimitiveDLSet()
        )
      }
    ).toDLSequence()
}


