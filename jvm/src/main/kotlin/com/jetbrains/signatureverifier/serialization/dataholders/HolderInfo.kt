package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.Holder

@Serializable
data class HolderInfo(
  val baseCertificateId: IssuerSerialInfo?,
  val entityName: List<GeneralNameInfo>?,
  val objectDigestInfo: ObjectDigestInfo?,
  val version: Int
) : EncodableInfo {

  constructor(holder: Holder) : this(
    holder.baseCertificateID?.let { IssuerSerialInfo(it) },
    holder.entityName?.let { it.names.map { name -> GeneralNameInfo(name) } },
    holder.objectDigestInfo?.let { ObjectDigestInfo(it) },
    holder.version
  )

  override fun toPrimitive(): ASN1Primitive = when (version) {
    0 -> when (entityName) {
      null ->
        TaggedObjectInfo.getTaggedObject(
          true,
          0,
          baseCertificateId!!.toPrimitive()
        ).toASN1Primitive()

      else ->
        TaggedObjectInfo.getTaggedObject(
          true,
          1,
          entityName.toPrimitiveDLSequence()
        ).toASN1Primitive()
    }

    1 -> listOf(
      baseCertificateId?.let {
        TaggedObjectInfo.getTaggedObject(
          false,
          0,
          it.toPrimitive()
        )
      },
      entityName?.let {
        TaggedObjectInfo.getTaggedObject(
          false,
          1,
          it.toPrimitiveDLSequence()
        )
      },
      objectDigestInfo?.let {
        TaggedObjectInfo.getTaggedObject(
          false,
          2,
          it.toPrimitive()
        )
      },
    ).toDLSequence()

    else -> throw IllegalArgumentException("Unexpected version $version")
  }
}