package com.jetbrains.signatureverifier.bouncycastle.tsp

import com.jetbrains.signatureverifier.bouncycastle.tsp.TSPUtil.validateCertificate
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.tsp.TSPValidationException
import java.lang.IllegalArgumentException
import org.bouncycastle.cms.CMSProcessable
import java.io.ByteArrayOutputStream
import org.bouncycastle.asn1.tsp.TSTInfo
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ess.SigningCertificate
import org.bouncycastle.asn1.ess.ESSCertID
import org.bouncycastle.asn1.ess.SigningCertificateV2
import org.bouncycastle.asn1.ess.ESSCertIDv2
import org.bouncycastle.cms.CMSException
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.cms.SignerId
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509AttributeCertificateHolder
import kotlin.Throws
import org.bouncycastle.cms.SignerInformationVerifier
import java.io.IOException
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.IssuerSerial
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.Store

/**
 * Carrier class for a TimeStampToken.
 */
class TimeStampToken(var tsToken: CMSSignedData) {
  val tsaSignerInfo: SignerInformation
  val timeStampInfo: TimeStampTokenInfo
  private val certID: CertID

  constructor(contentInfo: ContentInfo) : this(getSignedData(contentInfo)) {}

  init {
    if (tsToken.signedContentTypeOID != PKCSObjectIdentifiers.id_ct_TSTInfo.id) {
      throw TSPValidationException("ContentInfo object not for a time stamp.")
    }
    val signers = tsToken.signerInfos.signers
    require(signers.size == 1) {
      ("Time-stamp token signed by "
          + signers.size
          + " signers, but it must contain just the TSA signature.")
    }
    tsaSignerInfo = signers.iterator().next() as SignerInformation
    try {
      val content: CMSProcessable = tsToken.signedContent
      val bOut = ByteArrayOutputStream()
      content.write(bOut)
      timeStampInfo = TimeStampTokenInfo(TSTInfo.getInstance(ASN1Primitive.fromByteArray(bOut.toByteArray())))
      var attr = tsaSignerInfo.signedAttributes[PKCSObjectIdentifiers.id_aa_signingCertificate]
      if (attr != null) {
        val signCert = SigningCertificate.getInstance(attr.attrValues.getObjectAt(0))
        certID = CertID(ESSCertID.getInstance(signCert.certs[0]))
      } else {
        attr = tsaSignerInfo.signedAttributes[PKCSObjectIdentifiers.id_aa_signingCertificateV2]
        if (attr == null) {
          throw TSPValidationException("no signing certificate attribute found, time stamp invalid.")
        }
        val signCertV2 = SigningCertificateV2.getInstance(attr.attrValues.getObjectAt(0))
        certID = CertID(ESSCertIDv2.getInstance(signCertV2.certs[0]))
      }
    } catch (e: CMSException) {
      throw TSPException(e.message, e.underlyingException)
    }
  }

  val sID: SignerId
    get() = tsaSignerInfo.sid
  val signedAttributes: AttributeTable
    get() = tsaSignerInfo.signedAttributes
  val unsignedAttributes: AttributeTable
    get() = tsaSignerInfo.unsignedAttributes
  val certificates: Store<X509CertificateHolder>
    get() = tsToken.certificates
  val cRLs: Store<X509CRLHolder>
    get() = tsToken.crLs
  val attributeCertificates: Store<X509AttributeCertificateHolder>
    get() = tsToken.attributeCertificates

  /**
   * Validate the time stamp token.
   *
   *
   * To be valid the token must be signed by the passed in certificate and
   * the certificate must be the one referred to by the SigningCertificate
   * attribute included in the hashed attributes of the token. The
   * certificate must also have the ExtendedKeyUsageExtension with only
   * KeyPurposeId.id_kp_timeStamping and have been valid at the time the
   * timestamp was created.
   *
   *
   *
   * A successful call to validate means all the above are true.
   *
   *
   * @param sigVerifier the content verifier create the objects required to verify the CMS object in the timestamp.
   * @throws TSPException if an exception occurs in processing the token.
   * @throws TSPValidationException if the certificate or signature fail to be valid.
   * @throws IllegalArgumentException if the sigVerifierProvider has no associated certificate.
   */
  @Throws(TSPException::class, TSPValidationException::class)
  fun validate(
    sigVerifier: SignerInformationVerifier
  ) {
    require(sigVerifier.hasAssociatedCertificate()) { "verifier provider needs an associated certificate" }
    try {
      val certHolder = sigVerifier.associatedCertificate
      val calc = sigVerifier.getDigestCalculator(certID.hashAlgorithm)
      val cOut = calc.outputStream
      cOut.write(certHolder.encoded)
      cOut.close()
      if (!Arrays.constantTimeAreEqual(certID.certHash, calc.digest)) {
        throw TSPValidationException("certificate hash does not match certID hash.")
      }
      if (certID.issuerSerial != null) {
        val issuerSerial = IssuerAndSerialNumber(certHolder.toASN1Structure())
        if (!certID.issuerSerial!!.getSerial().equals(issuerSerial.serialNumber)) {
          throw TSPValidationException("certificate serial number does not match certID for signature.")
        }
        val names: Array<GeneralName> = certID.issuerSerial!!.getIssuer().getNames()
        var found = false
        for (i in names.indices) {
          if (names[i].tagNo == 4 && X500Name.getInstance(names[i].name) == X500Name.getInstance(issuerSerial.name)) {
            found = true
            break
          }
        }
        if (!found) {
          throw TSPValidationException("certificate name does not match certID for signature. ")
        }
      }
      validateCertificate(certHolder)
      if (!certHolder.isValidOn(timeStampInfo.genTime)) {
        throw TSPValidationException("certificate not valid when time stamp created.")
      }
      if (!tsaSignerInfo.verify(sigVerifier)) {
        throw TSPValidationException("signature not created by certificate.")
      }
    } catch (e: CMSException) {
      if (e.underlyingException != null) {
        throw TSPException(e.message, e.underlyingException)
      } else {
        throw TSPException("CMS exception: $e", e)
      }
    } catch (e: IOException) {
      throw TSPException("problem processing certificate: $e", e)
    } catch (e: OperatorCreationException) {
      throw TSPException("unable to create digest: " + e.message, e)
    }
  }

  /**
   * Return true if the signature on time stamp token is valid.
   *
   *
   * Note: this is a much weaker proof of correctness than calling validate().
   *
   *
   * @param sigVerifier the content verifier create the objects required to verify the CMS object in the timestamp.
   * @return true if the signature matches, false otherwise.
   * @throws TSPException if the signature cannot be processed or the provider cannot match the algorithm.
   */
  @Throws(TSPException::class)
  fun isSignatureValid(
    sigVerifier: SignerInformationVerifier?
  ): Boolean {
    return try {
      tsaSignerInfo.verify(sigVerifier)
    } catch (e: CMSException) {
      if (e.underlyingException != null) {
        throw TSPException(e.message, e.underlyingException)
      } else {
        throw TSPException("CMS exception: $e", e)
      }
    }
  }

  /**
   * Return the underlying CMSSignedData object.
   *
   * @return the underlying CMS structure.
   */
  fun toCMSSignedData(): CMSSignedData {
    return tsToken
  }

  /**
   * Return a ASN.1 encoded byte stream representing the encoded object.
   *
   * @throws IOException if encoding fails.
   */
  @get:Throws(IOException::class)
  val encoded: ByteArray
    get() = tsToken.getEncoded(ASN1Encoding.DL)

  /**
   * return the ASN.1 encoded representation of this object using the specified encoding.
   *
   * @param encoding the ASN.1 encoding format to use ("BER", "DL", or "DER").
   */
  @Throws(IOException::class)
  fun getEncoded(encoding: String?): ByteArray {
    return tsToken.getEncoded(encoding)
  }

  // perhaps this should be done using an interface on the ASN.1 classes...
  inner class CertID {
    private var certID: ESSCertID?
    private var certIDv2: ESSCertIDv2?

    internal constructor(certID: ESSCertID?) {
      this.certID = certID
      certIDv2 = null
    }

    internal constructor(certID: ESSCertIDv2?) {
      certIDv2 = certID
      this.certID = null
    }

    val hashAlgorithm: AlgorithmIdentifier
      get() = if (certID != null) {
        AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)
      } else {
        certIDv2!!.hashAlgorithm
      }
    val certHash: ByteArray
      get() = if (certID != null) {
        certID!!.certHash
      } else {
        certIDv2!!.certHash
      }
    val issuerSerial: IssuerSerial?
      get() = if (certID != null) {
        certID!!.issuerSerial
      } else {
        certIDv2!!.issuerSerial
      }
  }

  companion object {
    @Throws(TSPException::class)
    private fun getSignedData(contentInfo: ContentInfo): CMSSignedData {
      return try {
        CMSSignedData(contentInfo)
      } catch (e: CMSException) {
        throw TSPException("TSP parsing error: " + e.message, e.cause)
      }
    }
  }
}