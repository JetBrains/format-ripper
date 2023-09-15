package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData
import com.jetbrains.signatureverifier.serialization.*
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.SignedData
import java.math.BigInteger

@Serializable
data class SignedDataInfo(
  @Serializable(BigIntegerSerializer::class)
  val version: BigInteger,
  val digestAlgorithmsInfo: List<AlgorithmInfo>,
  val encapContentInfo: EncapContentInfo,
  val certificates: List<CertificateInfo>,
  val crls: List<EncodableInfo>?,
  val signerInfos: List<SignerInfo>
) : EncodableInfo {

  constructor(signedData: CMSSignedData) : this(
    signedData.signedData.version.value,
    signedData.digestAlgorithmIDs.map { AlgorithmInfo(it) },
    EncapContentInfo.getInstance(signedData.signedData.encapContentInfo),
    signedData.certificates.getMatches(null).toList().map { certificateHolder ->
      CertificateInfo.getInstance(certificateHolder)
    },
    signedData.signedData.crLs?.map { it.toASN1Primitive().toEncodableInfo() },
    signedData.signerInfos.signers.map { SignerInfo(it) }
  )

  override fun toPrimitive(): ASN1Primitive =
    listOf(
      ASN1Integer(version),
      digestAlgorithmsInfo.toPrimitiveDLSet(),
      encapContentInfo.toPrimitive(),
      TaggedObjectInfo.getTaggedObject(
        false,
        0,
        certificates.toPrimitiveDLSet()
      ),
      crls?.toPrimitiveList()?.toDLSet()?.toASN1Primitive(),
      signerInfos.toPrimitiveDLSet().toASN1Primitive()
    ).toDLSequence()

  fun toSignature(encoding: String = "DER") =
    SignedData.getInstance(toPrimitive()).toContentInfo().getEncoded(encoding)
}