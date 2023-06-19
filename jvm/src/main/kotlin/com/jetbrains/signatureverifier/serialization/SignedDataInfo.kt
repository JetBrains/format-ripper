package com.jetbrains.signatureverifier.serialization

import TaggedObjectMetaInfo
import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.util.CollectionStore
import java.math.BigInteger

@Serializable
data class SignedDataInfo(
  @Serializable(BigIntegerSerializer::class)
  val version: BigInteger,
  val digestAlgorithmsInfo: DigestAlgorithmsInfo,
  val encapContentInfo: EncapContentInfo,
  val certificates: List<CertificateInfo>,
  val signerInfos: List<SignerInfo>
) : EncodableInfo {
  override fun toPrimitive(): ASN1Primitive =
    listOf(
      ASN1Integer(version),
      digestAlgorithmsInfo.toPrimitive(),
      encapContentInfo.toPrimitive(),
      TaggedObjectInfo.getTaggedObjectWithMetaInfo(
        TaggedObjectMetaInfo(0, 2),
        recreateCertificatesFromStore(
          CollectionStore(certificates.map {
            it.toX509CertificateHolder()
          })
        ).toASN1Primitive()
      ),
      signerInfos.map { it.toPrimitive() }.toDLSet().toASN1Primitive()
    ).toDLSequence()

  constructor(signedData: CMSSignedData) : this(
    signedData.signedData.version.value,
    DigestAlgorithmsInfo.getInstance(signedData.digestAlgorithmIDs),
    EncapContentInfo.getInstance(signedData.signedData.encapContentInfo),
    signedData.certificates.getMatches(null).toList().map { certificateHolder ->
      CertificateInfo.getInstance(certificateHolder)
    },
    signedData.signerInfos.signers.map { SignerInfo(it) }
  )

}