package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.toDLSequence
import com.jetbrains.signatureverifier.serialization.toPrimitiveDLSequence
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x509.AttCertIssuer
import org.bouncycastle.asn1.x509.V2Form

@Serializable
data class AttCertIssuerInfo(
  val issuerName: List<GeneralNameInfo>,
  val baseCertificateId: IssuerSerialInfo?,
  val objectDigestInfo: ObjectDigestInfo?,
) : EncodableInfo {

  constructor(issuer: AttCertIssuer) : this(
    (issuer.issuer as V2Form).issuerName.names.map { GeneralNameInfo(it) },
    (issuer.issuer as V2Form).baseCertificateID?.let { IssuerSerialInfo(it) },
    (issuer.issuer as V2Form).objectDigestInfo?.let { ObjectDigestInfo(it) },
  )

  override fun toPrimitive(): ASN1Primitive =
    AttCertIssuer.getInstance(
      V2Form.getInstance(
        listOf(
          issuerName.toPrimitiveDLSequence(),
          baseCertificateId?.toPrimitive(),
          objectDigestInfo?.toPrimitive()
        ).toDLSequence()
      )
    ).toASN1Primitive()
}