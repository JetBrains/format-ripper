package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.cms.Attribute

@Serializable
data class SignerInformation(
  val version: Int,
  val sid: SignerIdentifierInfo,
  val digestAlgorithm: AlgorithmInfo,
  val authenticatedAttributes: List<AttributeInfo>,
  val digestEncryptionAlgorithm: AlgorithmInfo,
  val encryptedDigest: StringInfo,
  val unauthenticatedAttributes: List<AttributeInfo>?
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive = listToDLSequence(
    listOf(
      ASN1Integer(version.toLong()),
      sid.toPrimitive(),
      digestAlgorithm.toPrimitive(),
      TaggedObjectInfo.getTaggedObjectWithMetaInfo(
        TaggedObjectMetaInfo(0, 2),
        listToDLSet(authenticatedAttributes.map { it.toPrimitive() })
      ),
      digestEncryptionAlgorithm.toPrimitive(),
      encryptedDigest.toPrimitive(),
      (if (unauthenticatedAttributes == null) {
        null
      } else
        TaggedObjectInfo.getTaggedObjectWithMetaInfo(
          TaggedObjectMetaInfo(1, 2),
          listToDLSet(unauthenticatedAttributes.map { it.toPrimitive() })
        )),
    )
  )

  constructor(signer: SignerInformation) : this(
    signer.version,
    SignerIdentifierInfo(signer.sID),
    AlgorithmInfo(signer.digestAlgorithmID),
    signer.toASN1Structure().authenticatedAttributes.map {
      (it as DLSequence).first()
    }.map {
      AttributeInfo.getInstance(
        signer.signedAttributes?.get(it as ASN1ObjectIdentifier) as Attribute
      )
    },
    AlgorithmInfo(signer.encryptionAlgorithm),
    StringInfo.getInstance(signer.toASN1Structure().encryptedDigest),
    signer.toASN1Structure().unauthenticatedAttributes?.map {
      (it as DLSequence).first()
    }?.map {
      AttributeInfo.getInstance(
        signer.unsignedAttributes?.get(it as ASN1ObjectIdentifier) as Attribute
      )
    }
  )
}


