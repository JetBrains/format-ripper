package com.jetbrains.signatureverifier.bouncycastle.cms

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BEROctetStringGenerator
import org.bouncycastle.asn1.BERSet
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers
import org.bouncycastle.asn1.ocsp.OCSPResponse
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.SignerInfoGenerator
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.util.Store
import org.bouncycastle.util.Strings
import org.bouncycastle.util.io.Streams
import org.bouncycastle.util.io.TeeInputStream
import org.bouncycastle.util.io.TeeOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

internal object CMSUtils {
  private val des: MutableSet<String> = HashSet()
  private val mqvAlgs: MutableSet<ASN1ObjectIdentifier> = HashSet()
  private val ecAlgs: MutableSet<ASN1ObjectIdentifier> = HashSet()
  private val gostAlgs: MutableSet<ASN1ObjectIdentifier> = HashSet()

  init {
    des.add("DES")
    des.add("DESEDE")
    des.add(OIWObjectIdentifiers.desCBC.id)
    des.add(PKCSObjectIdentifiers.des_EDE3_CBC.id)
    des.add(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.id)
    mqvAlgs.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme)
    mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme)
    mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme)
    mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme)
    mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme)
    ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme)
    ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme)
    ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme)
    gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH)
    gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256)
    gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512)
  }

  fun isMQV(algorithm: ASN1ObjectIdentifier?): Boolean {
    return mqvAlgs.contains(algorithm)
  }

  fun isEC(algorithm: ASN1ObjectIdentifier?): Boolean {
    return ecAlgs.contains(algorithm)
  }

  fun isGOST(algorithm: ASN1ObjectIdentifier?): Boolean {
    return gostAlgs.contains(algorithm)
  }

  fun isRFC2631(algorithm: ASN1ObjectIdentifier): Boolean {
    return algorithm.equals(PKCSObjectIdentifiers.id_alg_ESDH) || algorithm.equals(PKCSObjectIdentifiers.id_alg_SSDH)
  }

  fun isDES(algorithmID: String?): Boolean {
    val name = Strings.toUpperCase(algorithmID)
    return des.contains(name)
  }

  fun isEquivalent(algId1: AlgorithmIdentifier?, algId2: AlgorithmIdentifier?): Boolean {
    if (algId1 == null || algId2 == null) {
      return false
    }
    if (!algId1.algorithm.equals(algId2.algorithm)) {
      return false
    }
    val params1 = algId1.parameters
    val params2 = algId2.parameters
    return if (params1 != null) {
      params1 == params2 || params1 == DERNull.INSTANCE && params2 == null
    } else params2 == null || params2 == DERNull.INSTANCE
  }

  @Throws(CMSException::class)
  fun readContentInfo(
    input: ByteArray?
  ): ContentInfo {
    // enforce limit checking as from a byte array
    return readContentInfo(ASN1InputStream(input))
  }

  @Throws(CMSException::class)
  fun readContentInfo(
    input: InputStream?
  ): ContentInfo {
    // enforce some limit checking
    return readContentInfo(ASN1InputStream(input))
  }

  fun convertToBERSet(digestAlgs: Set<AlgorithmIdentifier>): ASN1Set {
    return DLSet(digestAlgs.toTypedArray())
  }

  fun addDigestAlgs(digestAlgs: MutableSet<AlgorithmIdentifier>, signer: SignerInformation, dgstAlgFinder: DigestAlgorithmIdentifierFinder?) {
    digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(signer.digestAlgorithmID, dgstAlgFinder!!))
    val counterSignaturesStore = signer.getCounterSignatures()
    val counterSignatureIt: Iterator<SignerInformation?> = counterSignaturesStore.iterator()
    while (counterSignatureIt.hasNext()) {
      digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(counterSignatureIt.next()!!.digestAlgorithmID, dgstAlgFinder))
    }
  }

  @Throws(CMSException::class)
  fun getCertificatesFromStore(certStore: Store<X509CertificateHolder>): List<Certificate> {
    val certs = mutableListOf<Certificate>()
    return try {
      val it: Iterator<*> = certStore.getMatches(null).iterator()
      while (it.hasNext()) {
        val c = it.next() as X509CertificateHolder
        certs.add(c.toASN1Structure())
      }
      certs
    } catch (e: ClassCastException) {
      throw CMSException("error processing certs", e)
    }
  }

  @Throws(CMSException::class)
  fun getAttributeCertificatesFromStore(attrStore: Store<X509AttributeCertificateHolder>): List<DERTaggedObject> {
    val certs = mutableListOf<DERTaggedObject>()
    return try {
      val it = attrStore.getMatches(null).iterator()
      while (it.hasNext()) {
        val attrCert = it.next() as X509AttributeCertificateHolder
        certs.add(DERTaggedObject(false, 2, attrCert.toASN1Structure()))
      }
      certs
    } catch (e: ClassCastException) {
      throw CMSException("error processing certs", e)
    }
  }

  @Throws(CMSException::class)
  fun getCRLsFromStore(crlStore: Store<X509CRLHolder>): List<*> {
    val crls = mutableListOf<Any>()
    return try {
      val it: Iterator<*> = crlStore.getMatches(null).iterator()
      while (it.hasNext()) {
        val rev = it.next()!!
        if (rev is X509CRLHolder) {
          crls.add(rev.toASN1Structure())
        } else if (rev is OtherRevocationInfoFormat) {
          val infoFormat = OtherRevocationInfoFormat.getInstance(rev)
          validateInfoFormat(infoFormat)
          crls.add(DERTaggedObject(false, 1, infoFormat))
        } else if (rev is ASN1TaggedObject) {
          crls.add(rev)
        }
      }
      crls
    } catch (e: ClassCastException) {
      throw CMSException("error processing certs", e)
    }
  }

  private fun validateInfoFormat(infoFormat: OtherRevocationInfoFormat) {
    if (CMSObjectIdentifiers.id_ri_ocsp_response.equals(infoFormat.infoFormat)) {
      val resp = OCSPResponse.getInstance(infoFormat.info)
      require(OCSPResponseStatus.SUCCESSFUL == resp.responseStatus.intValue) { "cannot add unsuccessful OCSP response to CMS SignedData" }
    }
  }

  fun getOthersFromStore(otherRevocationInfoFormat: ASN1ObjectIdentifier?, otherRevocationInfos: Store<OtherRevocationInfoFormat>): Collection<*> {
    val others = mutableListOf<DERTaggedObject>()
    val it: Iterator<*> = otherRevocationInfos.getMatches(null).iterator()
    while (it.hasNext()) {
      val info = it.next() as ASN1Encodable
      val infoFormat = OtherRevocationInfoFormat(otherRevocationInfoFormat, info)
      validateInfoFormat(infoFormat)
      others.add(DERTaggedObject(false, 1, infoFormat))
    }
    return others
  }

  fun createBerSetFromList(derObjects: List<*>): ASN1Set {
    val v = ASN1EncodableVector()
    val it = derObjects.iterator()
    while (it.hasNext()) {
      v.add(it.next() as ASN1Encodable?)
    }
    return BERSet(v)
  }

  fun createDerSetFromList(derObjects: List<*>): ASN1Set {
    val v = ASN1EncodableVector()
    val it = derObjects.iterator()
    while (it.hasNext()) {
      v.add(it.next() as ASN1Encodable?)
    }
    return DERSet(v)
  }

  @Throws(IOException::class)
  fun createBEROctetOutputStream(
    s: OutputStream?,
    tagNo: Int, isExplicit: Boolean, bufferSize: Int
  ): OutputStream {
    val octGen = BEROctetStringGenerator(s, tagNo, isExplicit)
    return if (bufferSize != 0) {
      octGen.getOctetOutputStream(ByteArray(bufferSize))
    } else octGen.octetOutputStream
  }

  @Throws(CMSException::class)
  private fun readContentInfo(
    `in`: ASN1InputStream
  ): ContentInfo {
    return try {
      val info = ContentInfo.getInstance(`in`.readObject()) ?: throw CMSException("No content found.")
      info
    } catch (e: IOException) {
      throw CMSException("IOException reading content.", e)
    } catch (e: ClassCastException) {
      throw CMSException("Malformed content.", e)
    } catch (e: IllegalArgumentException) {
      throw CMSException("Malformed content.", e)
    }
  }

  @Throws(IOException::class)
  fun streamToByteArray(
    `in`: InputStream?
  ): ByteArray {
    return Streams.readAll(`in`)
  }

  @Throws(IOException::class)
  fun streamToByteArray(
    `in`: InputStream?,
    limit: Int
  ): ByteArray {
    return Streams.readAllLimited(`in`, limit)
  }

  fun attachDigestsToInputStream(digests: Collection<*>, s: InputStream?): InputStream? {
    var result = s
    val it = digests.iterator()
    while (it.hasNext()) {
      val digest = it.next() as DigestCalculator
      result = TeeInputStream(result, digest.outputStream)
    }
    return result
  }

  fun attachSignersToOutputStream(signers: Collection<*>, s: OutputStream?): OutputStream? {
    var result = s
    val it = signers.iterator()
    while (it.hasNext()) {
      val signerGen = it.next() as SignerInfoGenerator
      result = getSafeTeeOutputStream(result, signerGen.calculatingOutputStream)
    }
    return result
  }

  fun getSafeOutputStream(s: OutputStream?): OutputStream {
    return s ?: NullOutputStream()
  }

  fun getSafeTeeOutputStream(
    s1: OutputStream?,
    s2: OutputStream?
  ): OutputStream {
    return if (s1 == null) getSafeOutputStream(s2) else s2?.let { TeeOutputStream(s1, it) } ?: getSafeOutputStream(s1)
  }
}