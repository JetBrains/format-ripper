package com.jetbrains.signatureverifier.bouncycastle.tsp

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
import org.bouncycastle.asn1.gm.GMObjectIdentifiers
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.operator.DigestCalculatorProvider
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.tsp.TSPIOException
import org.bouncycastle.tsp.TSPValidationException
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.Integers
import java.io.IOException
import java.util.*

object TSPUtil {
  private val EMPTY_LIST = Collections.unmodifiableList(ArrayList<Any?>())
  private val digestLengths = mutableMapOf<String, Int>()
  private val digestNames = mutableMapOf<String, String>()

  init {
    digestLengths[PKCSObjectIdentifiers.md5.id] = Integers.valueOf(16)
    digestLengths[OIWObjectIdentifiers.idSHA1.id] = Integers.valueOf(20)
    digestLengths[NISTObjectIdentifiers.id_sha224.id] = Integers.valueOf(28)
    digestLengths[NISTObjectIdentifiers.id_sha256.id] = Integers.valueOf(32)
    digestLengths[NISTObjectIdentifiers.id_sha384.id] = Integers.valueOf(48)
    digestLengths[NISTObjectIdentifiers.id_sha512.id] = Integers.valueOf(64)
    digestLengths[TeleTrusTObjectIdentifiers.ripemd128.id] = Integers.valueOf(16)
    digestLengths[TeleTrusTObjectIdentifiers.ripemd160.id] = Integers.valueOf(20)
    digestLengths[TeleTrusTObjectIdentifiers.ripemd256.id] = Integers.valueOf(32)
    digestLengths[CryptoProObjectIdentifiers.gostR3411.id] = Integers.valueOf(32)
    digestLengths[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.id] = Integers.valueOf(32)
    digestLengths[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.id] = Integers.valueOf(64)
    digestLengths[GMObjectIdentifiers.sm3.id] = Integers.valueOf(32)
    digestNames[PKCSObjectIdentifiers.md5.id] = "MD5"
    digestNames[OIWObjectIdentifiers.idSHA1.id] = "SHA1"
    digestNames[NISTObjectIdentifiers.id_sha224.id] = "SHA224"
    digestNames[NISTObjectIdentifiers.id_sha256.id] = "SHA256"
    digestNames[NISTObjectIdentifiers.id_sha384.id] = "SHA384"
    digestNames[NISTObjectIdentifiers.id_sha512.id] = "SHA512"
    digestNames[PKCSObjectIdentifiers.sha1WithRSAEncryption.id] = "SHA1"
    digestNames[PKCSObjectIdentifiers.sha224WithRSAEncryption.id] = "SHA224"
    digestNames[PKCSObjectIdentifiers.sha256WithRSAEncryption.id] = "SHA256"
    digestNames[PKCSObjectIdentifiers.sha384WithRSAEncryption.id] = "SHA384"
    digestNames[PKCSObjectIdentifiers.sha512WithRSAEncryption.id] = "SHA512"
    digestNames[TeleTrusTObjectIdentifiers.ripemd128.id] = "RIPEMD128"
    digestNames[TeleTrusTObjectIdentifiers.ripemd160.id] = "RIPEMD160"
    digestNames[TeleTrusTObjectIdentifiers.ripemd256.id] = "RIPEMD256"
    digestNames[CryptoProObjectIdentifiers.gostR3411.id] = "GOST3411"
    digestNames[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.id] = "GOST3411-2012-256"
    digestNames[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.id] = "GOST3411-2012-512"
    digestNames[GMObjectIdentifiers.sm3.id] = "SM3"
  }

  /**
   * Fetches the signature time-stamp attributes from a SignerInformation object.
   * Checks that the MessageImprint for each time-stamp matches the signature field.
   * (see RFC 3161 Appendix A).
   *
   * @param signerInfo a SignerInformation to search for time-stamps
   * @param digCalcProvider provider for digest calculators
   * @return a collection of TimeStampToken objects
   * @throws TSPValidationException
   */
  @Throws(TSPValidationException::class)
  fun getSignatureTimestamps(signerInfo: SignerInformation, digCalcProvider: DigestCalculatorProvider): Collection<*> {
    val timestamps = mutableListOf<TimeStampToken>()
    val unsignedAttrs = signerInfo.unsignedAttributes
    if (unsignedAttrs != null) {
      val allTSAttrs = unsignedAttrs.getAll(
        PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
      )
      for (i in 0 until allTSAttrs.size()) {
        val tsAttr = allTSAttrs[i] as Attribute
        val tsAttrValues = tsAttr.attrValues
        for (j in 0 until tsAttrValues.size()) {
          try {
            val contentInfo = ContentInfo.getInstance(tsAttrValues.getObjectAt(j))
            val timeStampToken = TimeStampToken(contentInfo)
            val tstInfo = timeStampToken.timeStampInfo
            val digCalc = digCalcProvider[tstInfo.hashAlgorithm]
            val dOut = digCalc.outputStream
            dOut.write(signerInfo.signature)
            dOut.close()
            val expectedDigest = digCalc.digest
            if (!Arrays.constantTimeAreEqual(expectedDigest, tstInfo.messageImprintDigest)) {
              throw TSPValidationException("Incorrect digest in message imprint")
            }
            timestamps.add(timeStampToken)
          } catch (e: OperatorCreationException) {
            throw TSPValidationException("Unknown hash algorithm specified in timestamp")
          } catch (e: Exception) {
            throw TSPValidationException("Timestamp could not be parsed")
          }
        }
      }
    }
    return timestamps
  }

  /**
   * Validate the passed in certificate as being of the correct type to be used
   * for time stamping. To be valid it must have an ExtendedKeyUsage extension
   * which has a key purpose identifier of id-kp-timeStamping.
   *
   * @param cert the certificate of interest.
   * @throws TSPValidationException if the certificate fails on one of the check points.
   */
  @JvmStatic
  @Throws(TSPValidationException::class)
  fun validateCertificate(
    cert: X509CertificateHolder
  ) {
    /*
     * We do not really care about this
     * https://github.com/bcgit/bc-csharp/issues/314
    */
    //require(cert.toASN1Structure().versionNumber == 3) { "Certificate must have an ExtendedKeyUsage extension." }

    val ext = cert.getExtension(Extension.extendedKeyUsage)

    if (ext == null)
      throw TSPValidationException("Certificate must have an ExtendedKeyUsage extension.")

    /*
    * We do not really care about this
    * https://github.com/bcgit/bc-csharp/issues/314
    */
    //if (!ext.isCritical) {
    //  throw TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.")
    //}

    val extKey = ExtendedKeyUsage.getInstance(ext.parsedValue)
    if (!extKey.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || extKey.size() != 1) {
      throw TSPValidationException("ExtendedKeyUsage not solely time stamping.")
    }
  }

  @Throws(TSPException::class)
  fun getDigestLength(
    digestAlgOID: String?
  ): Int {
    val length = digestLengths[digestAlgOID]
    if (length != null) {
      return length.toInt()
    }
    throw TSPException("digest algorithm cannot be found.")
  }

  fun getExtensionOIDs(extensions: Extensions?): List<*> {
    return if (extensions == null) {
      EMPTY_LIST
    } else Collections.unmodifiableList(java.util.Arrays.asList(*extensions.extensionOIDs))
  }

  @Throws(TSPIOException::class)
  fun addExtension(extGenerator: ExtensionsGenerator, oid: ASN1ObjectIdentifier?, isCritical: Boolean, value: ASN1Encodable?) {
    try {
      extGenerator.addExtension(oid, isCritical, value)
    } catch (e: IOException) {
      throw TSPIOException("cannot encode extension: " + e.message, e)
    }
  }
}