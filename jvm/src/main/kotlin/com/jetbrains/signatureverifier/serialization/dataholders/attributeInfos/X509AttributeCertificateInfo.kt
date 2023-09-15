package com.jetbrains.signatureverifier.serialization.dataholders

import com.jetbrains.signatureverifier.serialization.*
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.AttCertIssuer
import org.bouncycastle.asn1.x509.AttCertValidityPeriod
import org.bouncycastle.asn1.x509.Holder
import org.bouncycastle.cert.X509AttributeCertificateHolder
import java.math.BigInteger
import java.util.*

@Serializable
data class X509AttributeCertificateInfo(
  @Serializable(BigIntegerSerializer::class)
  val version: BigInteger,
  val holderInfo: HolderInfo,
  val issuer: AttCertIssuerInfo,
  val signatureInfo: AlgorithmInfo,
  @Serializable(BigIntegerSerializer::class)
  val serialNumber: BigInteger,
  @Serializable(DateSerializer::class)
  val startDate: Date,
  @Serializable(DateSerializer::class)
  val endDate: Date,
  val attributes: List<AttributeInfo>,
  val issuerUniqueId: TextualInfo?,
  val extensions: List<ExtensionInfo>?
) : XCertificateInfo() {
  companion object {
    fun getInstance(certificateHolder: X509AttributeCertificateHolder):
      X509AttributeCertificateInfo =
      certificateHolder.toASN1Structure().acinfo.let { acinfo ->
        X509AttributeCertificateInfo(
          acinfo.version.value,
          HolderInfo(acinfo.holder),
          AttCertIssuerInfo(acinfo.issuer),
          AlgorithmInfo(acinfo.signature),
          acinfo.serialNumber.value,
          acinfo.attrCertValidityPeriod.notBeforeTime.date,
          acinfo.attrCertValidityPeriod.notAfterTime.date,
          acinfo.attributes.map { AttributeInfo.getInstance(Attribute.getInstance(it)) },
          acinfo.issuerUniqueID?.let { TextualInfo.getInstance(it) },
          acinfo.extensions?.let {
            it.extensionOIDs.map {oid->
              val extension = acinfo.extensions.getExtension(oid)
              ExtensionInfo(
                TextualInfo.getInstance(extension.extnId),
                certificateHolder.extensions.criticalExtensionOIDs.contains(extension.extnId),
                TextualInfo.getInstance(extension.extnValue)
              )
            }
          }
        )
      }
  }

  override fun toPrimitive(): ASN1Primitive = listOf(
    ASN1Integer(version),
    Holder.getInstance(holderInfo.toPrimitive()),
    AttCertIssuer.getInstance(issuer.toPrimitive()),
    AlgorithmIdentifier.getInstance(signatureInfo.toPrimitive()),
    ASN1Integer(serialNumber),
    AttCertValidityPeriod(
      ASN1GeneralizedTime(startDate),
      ASN1GeneralizedTime(endDate)
    ),
    attributes.toPrimitiveDLSequence(),
    issuerUniqueId?.toPrimitive(),
    extensions?.toPrimitiveList()?.toDLSequence()
  ).toDLSequence()
}