package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.util.ASN1Dump.dumpAsString
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.util.Store
import org.jetbrains.annotations.NotNull
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.*

object BcExt {
  fun ASN1Encodable.Dump(): String = dumpAsString(this)

  fun ASN1Encodable.DumpToConsole() = println(this.Dump())

  fun Certificate.SN(): String = this.serialNumber.value.toByteArray().ConvertToHexString().uppercase()

  fun Certificate.Thumbprint(): String = MessageDigest.getInstance("SHA1").digest(this.encoded).ConvertToHexString()

  fun X509CertificateHolder.Thumbprint(): String =
    MessageDigest.getInstance("SHA1").digest(this.encoded).ConvertToHexString()

  fun ByteArray.ConvertToHexString(): String = joinToString(separator = "") { "%02x".format(it) }

  /**
   * Extract the OCSP responder URL from certificate extension (OID 1.3.6.1.5.5.7.1.1)
   *
   * @return URL-string for request an OCSP responder
   */
  fun Certificate.GetOcspUrl(): String? {
    return getOcspUrl(this.tbsCertificate.extensions)
  }

  /**
   * Extract the OCSP responder URL from certificate extension (OID 1.3.6.1.5.5.7.1.1)
   *
   * @return URL-string for request an OCSP responder
   */
  fun X509CertificateHolder.GetOcspUrl(): String? {
    return getOcspUrl(this.extensions)
  }

  private fun getOcspUrl(extensions: Extensions?): String? {
    val authorityInformationAccess = AuthorityInformationAccess.fromExtensions(extensions) ?: return null
    val ocspAccessData =
      authorityInformationAccess.accessDescriptions.firstOrNull { it.accessMethod.equals(OIDs.OCSP) } ?: return null
    //rfc5280 GeneralName definition
    return (ocspAccessData.accessLocation.name as DERIA5String).string
  }

  /**
   * Extract the CRL distribution urls from certificate extension (OID 2.5.29.31)
  See rfc5280 section-4.2.1.13
   *
   * @return List of URL-strings from which CRL-files can be downloaded
   */
  fun X509CertificateHolder.GetCrlDistributionUrls(): MutableList<String> {
    val res = mutableListOf<String>()
    val crldp = CRLDistPoint.fromExtensions(this.extensions)
    if (crldp != null) {
      val dps: Array<DistributionPoint>?
      try {
        dps = crldp.distributionPoints
      } catch (e: Exception) {
        throw Exception("Distribution points could not be read.", e)
      }
      for (i in 0 until dps.count()) {
        val dpn = dps[i].distributionPoint
        // look for URIs in fullName
        if (dpn.type == DistributionPointName.FULL_NAME) {
          val genNames: Array<GeneralName> = GeneralNames.getInstance(dpn.name).names
          // look for an URI
          for (j in 0 until genNames.count()) {
            if (genNames[j].tagNo == GeneralName.uniformResourceIdentifier) {
              val location: String = ASN1IA5String.getInstance(genNames[j].name).string
              res.add(location)
            }
          }
        }
      }
    }
    return res
  }

  /**
   * Check if the certificate contains any CRL distribution points
   *
   */
  fun Certificate.HasCrlDistributionPoints(): Boolean {
    val crldp = CRLDistPoint.fromExtensions(this.tbsCertificate.extensions)
    return crldp != null
  }

  fun Certificate.IsSelfSigned(): Boolean {
    return this.issuer.equals(this.subject)
  }

  fun X509CertificateHolder.IsSelfSigned(): Boolean {
    return this.issuer.equals(this.subject)
  }

  fun Certificate.CanSignOcspResponses(): Boolean {
    return this.GetExtendedKeyUsage()?.contains(KeyPurposeId.id_kp_OCSPSigning.id) == true
  }

  fun X509CertificateHolder.CanSignOcspResponses(): Boolean {
    return this.GetExtendedKeyUsage()?.contains(KeyPurposeId.id_kp_OCSPSigning.id) == true
  }

  fun X509CertificateHolder.GetExtendedKeyUsage(): Collection<String>? {
    return getExtendedKeyUsage(this.extensions)
  }

  fun Certificate.GetExtendedKeyUsage(): Collection<String>? {
    return getExtendedKeyUsage(this.tbsCertificate.extensions)
  }

  private fun getExtendedKeyUsage(extensions: Extensions): Collection<String>? {
    val str = extensions.getExtensionParsedValue(ASN1ObjectIdentifier("2.5.29.37")) ?: return null

    try {
      val seq = ASN1Sequence.getInstance(str.FromExtensionValue())
      val list = mutableListOf<String>()

      for (oid: ASN1ObjectIdentifier in seq.map { it as ASN1ObjectIdentifier })
        list.add(oid.id)
      return list
    } catch (e: Exception) {
      throw CertificateParsingException("error processing extended key usage extension", e)
    }
  }

  private fun ASN1Encodable.FromExtensionValue(): ASN1Primitive? =
    ASN1Primitive.fromByteArray(this.toASN1Primitive().encoded)

  /**
   * Extract the authorityKeyIdentifier value from certificate extension (OID 2.5.29.35)
   * See rfc5280 section-4.2.1.1
   *
   * @return Hex string of the authorityKeyIdentifier
   */
  fun Certificate.GetAuthorityKeyIdentifier(): String? {
    val ki = AuthorityKeyIdentifier.fromExtensions(this.tbsCertificate.extensions)
    return ki?.keyIdentifier?.ConvertToHexString()
  }

  /**
   * Extract the authorityKeyIdentifier value from the certificate holder extension (OID 2.5.29.35)
   * See rfc5280 section-4.2.1.1
   *
   * @return Hex string of the authorityKeyIdentifier
   */
  fun X509CertificateHolder.GetAuthorityKeyIdentifier(): String? {
    val ki = AuthorityKeyIdentifier.fromExtensions(this.extensions)
    return ki?.keyIdentifier?.ConvertToHexString()
  }

  /**
   * Extract the subjectKeyIdentifier value from certificate extension (OID 2.5.29.14)
   * See rfc5280 section-4.2.1.2
   *
   * @return Hex string of the subjectKeyIdentifier
   */
  fun Certificate.GetSubjectKeyIdentifier(): String? {
    val ki = SubjectKeyIdentifier.fromExtensions(this.tbsCertificate.extensions)
    return ki?.keyIdentifier?.ConvertToHexString()
  }

  fun Certificate.GetSubjectKeyIdentifierRaw(): ByteArray? {
    val ki = SubjectKeyIdentifier.fromExtensions(this.tbsCertificate.extensions)
    return ki?.keyIdentifier
  }

  fun X509CertificateHolder.GetSubjectKeyIdentifierRaw(): ByteArray? {
    val ki = SubjectKeyIdentifier.fromExtensions(this.extensions)
    return ki?.keyIdentifier
  }

  internal fun Certificate.FormatId(): String {
    return "Issuer=${this.issuer}; SN=${this.SN()}"
  }

  internal fun X509CertificateHolder.FormatId(): String {
    val cert = this.toASN1Structure()
    return "Issuer=${cert.issuer}; SN=${cert.SN()}"
  }

  fun AttributeTable.GetFirstAttributeValue(@NotNull oid: ASN1ObjectIdentifier): ASN1Encodable? {
    val attr = this[oid]
    return if (attr != null && attr.attrValues.count() > 0) attr.attributeValues[0] else null
  }

  internal fun X509CertificateHolder.ToJavaX509Certificate(): X509Certificate {
    val cf = CertificateFactory.getInstance("X.509")
    return ByteArrayInputStream(this.encoded).use { cf.generateCertificate(it) as X509Certificate }
  }

  internal fun X509CRLHolder.ToJavaX509Crl(): X509CRL {
    val cf = CertificateFactory.getInstance("X.509")
    return ByteArrayInputStream(this.encoded).use { cf.generateCRL(it) as X509CRL }
  }

  internal fun Store<X509CertificateHolder>.ToJavaCertStore(): CertStore {
    val certs = this.getMatches(null).map { it.ToJavaX509Certificate() }
    val storeParams = CollectionCertStoreParameters(certs)
    return CertStore.getInstance("Collection", storeParams)
  }

  internal fun Store<X509CRLHolder>.ToJavaCrlStore(): CertStore {
    val crls = this.getMatches(null).map { it.ToJavaX509Crl() }
    val storeParams = CollectionCertStoreParameters(crls)
    return CertStore.getInstance("Collection", storeParams)
  }

  internal fun java.security.cert.Certificate.ToX509CertificateHolder(): X509CertificateHolder {
    return X509CertificateHolder(this.encoded)
  }
}
