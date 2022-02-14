package com.jetbrains.signatureverifier.bouncycastle.cms

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.BERSequence
import org.bouncycastle.asn1.DLSet
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509AttributeCertificateHolder
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessable
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.PKCS7ProcessableObject
import org.bouncycastle.cms.SignerInformationVerifierProvider
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.util.Encodable
import org.bouncycastle.util.Store
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.*

/**
 * general class for handling a pkcs7-signature message.
 *
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs
 * matches the given signer...
 *
 * <pre>
 * Store                   certStore = s.getCertificates();
 * SignerInformationStore  signers = s.getSignerInfos();
 * Collection              c = signers.getSigners();
 * Iterator                it = c.iterator();
 *
 * while (it.hasNext())
 * {
 * SignerInformation   signer = (SignerInformation)it.next();
 * Collection          certCollection = certStore.getMatches(signer.getSID());
 *
 * Iterator              certIt = certCollection.iterator();
 * X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
 *
 * if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
 * {
 * verified++;
 * }
 * }
</pre> *
 */
class CMSSignedData : Encodable {
  var signedData: SignedData
  var contentInfo: ContentInfo
  var signedContent: CMSTypedData? = null
  var signerInfoStore: SignerInformationStore? = null
  private var hashes: Map<*, *>? = null

  private constructor(
    c: CMSSignedData
  ) {
    signedData = c.signedData
    contentInfo = c.contentInfo
    signedContent = c.signedContent
    signerInfoStore = c.signerInfoStore
  }

  constructor(
    sigBlock: ByteArray?
  ) : this(CMSUtils.readContentInfo(sigBlock)) {
  }

  constructor(
    signedContent: CMSProcessable,
    sigBlock: ByteArray?
  ) : this(signedContent, CMSUtils.readContentInfo(sigBlock)) {
  }

  /**
   * Content with detached signature, digests precomputed
   *
   * @param hashes a map of precomputed digests for content indexed by name of hash.
   * @param sigBlock the signature object.
   */
  constructor(
    hashes: Map<*, *>?,
    sigBlock: ByteArray?
  ) : this(hashes, CMSUtils.readContentInfo(sigBlock)) {
  }

  /**
   * base constructor - content with detached signature.
   *
   * @param signedContent the content that was signed.
   * @param sigData the signature object.
   */
  constructor(
    signedContent: CMSProcessable,
    sigData: InputStream?
  ) : this(signedContent, CMSUtils.readContentInfo(ASN1InputStream(sigData))) {
  }

  /**
   * base constructor - with encapsulated content
   */
  constructor(
    sigData: InputStream?
  ) : this(CMSUtils.readContentInfo(sigData)) {
  }

  constructor(
    signedContent: CMSProcessable,
    sigData: ContentInfo
  ) {
    contentInfo = sigData
    signedData = getSignedDataX()

    if (signedContent is CMSTypedData) {
      this.signedContent = signedContent
    } else {
      this.signedContent = object : CMSTypedData {
        override fun getContentType(): ASN1ObjectIdentifier {
          return signedData.encapContentInfo.contentType
        }

        @Throws(IOException::class, CMSException::class)
        override fun write(out: OutputStream) {
          signedContent.write(out)
        }

        override fun getContent(): Any {
          return signedContent.content
        }
      }
    }
  }

  constructor(
    hashes: Map<*, *>?,
    sigData: ContentInfo
  ) {
    this.hashes = hashes
    contentInfo = sigData
    signedData = getSignedDataX()
  }

  constructor(
    sigData: ContentInfo
  ) {
    contentInfo = sigData
    signedData = getSignedDataX()

    //
    // this can happen if the signed message is sent simply to send a
    // certificate chain.
    //
    val content = signedData.encapContentInfo.content
    if (content != null) {
      if (content is ASN1OctetString) {
        signedContent = CMSProcessableByteArray(
          signedData.encapContentInfo.contentType,
          content.octets
        )
      } else {
        signedContent = PKCS7ProcessableObject(signedData.encapContentInfo.contentType, content)
      }
    } else {
      signedContent = null
    }
  }

  @Throws(CMSException::class)
  private fun getSignedDataX(): SignedData {
    return try {
      SignedData.getInstance(contentInfo.content)
    } catch (e: ClassCastException) {
      throw CMSException("Malformed content.", e)
    } catch (e: IllegalArgumentException) {
      throw CMSException("Malformed content.", e)
    }
  }

  /**
   * Return the version number for this object
   */
  val version: Int
    get() = signedData.version.intValueExact()

  /**
   * return the collection of signers that are associated with the
   * signatures for the message.
   */
  val signerInfos: SignerInformationStore
    get() {
      if (signerInfoStore == null) {
        val s = signedData.signerInfos
        val signerInfos = mutableListOf<SignerInformation>()
        for (i in 0 until s.size()) {
          val info = SignerInfo.getInstance(s.getObjectAt(i))
          val contentType = signedData.encapContentInfo.contentType
          if (hashes == null) {
            signerInfos.add(SignerInformation(info, contentType, signedContent, null))
          } else {
            val obj = hashes!!.keys.iterator().next()!!
            val hash = if (obj is String) hashes!![info.digestAlgorithm.algorithm.id] as ByteArray? else hashes!![info.digestAlgorithm.algorithm] as ByteArray?
            signerInfos.add(SignerInformation(info, contentType, null, hash))
          }
        }
        signerInfoStore = SignerInformationStore(signerInfos)
      }
      return signerInfoStore!!
    }

  /**
   * Return if this is object represents a detached signature.
   *
   * @return true if this message represents a detached signature, false otherwise.
   */
  val isDetachedSignature: Boolean
    get() = signedData.encapContentInfo.content == null && signedData.signerInfos.size() > 0

  /**
   * Return if this is object represents a certificate management message.
   *
   * @return true if the message has no signers or content, false otherwise.
   */
  val isCertificateManagementMessage: Boolean
    get() = signedData.encapContentInfo.content == null && signedData.signerInfos.size() == 0

  /**
   * Return any X.509 certificate objects in this SignedData structure as a Store of X509CertificateHolder objects.
   *
   * @return a Store of X509CertificateHolder objects.
   */
  val certificates: Store<X509CertificateHolder>
    get() = HELPER.getCertificates(signedData.certificates)

  /**
   * Return any X.509 CRL objects in this SignedData structure as a Store of X509CRLHolder objects.
   *
   * @return a Store of X509CRLHolder objects.
   */
  val cRLs: Store<X509CRLHolder>
    get() = HELPER.getCRLs(signedData.crLs)

  /**
   * Return any X.509 attribute certificate objects in this SignedData structure as a Store of X509AttributeCertificateHolder objects.
   *
   * @return a Store of X509AttributeCertificateHolder objects.
   */
  val attributeCertificates: Store<X509AttributeCertificateHolder>
    get() = HELPER.getAttributeCertificates(signedData.certificates)

  /**
   * Return any OtherRevocationInfo OtherRevInfo objects of the type indicated by otherRevocationInfoFormat in
   * this SignedData structure.
   *
   * @param otherRevocationInfoFormat OID of the format type been looked for.
   *
   * @return a Store of ASN1Encodable objects representing any objects of otherRevocationInfoFormat found.
   */
  fun getOtherRevocationInfo(otherRevocationInfoFormat: ASN1ObjectIdentifier): Store<*> {
    return HELPER.getOtherRevocationInfo(otherRevocationInfoFormat, signedData.crLs)
  }

  /**
   * Return the digest algorithm identifiers for the SignedData object
   *
   * @return the set of digest algorithm identifiers
   */
  val digestAlgorithmIDs: Set<AlgorithmIdentifier>
    get() {
      val digests: MutableSet<AlgorithmIdentifier> = HashSet(signedData.digestAlgorithms.size())
      val en = signedData.digestAlgorithms.objects
      while (en.hasMoreElements()) {
        digests.add(AlgorithmIdentifier.getInstance(en.nextElement()))
      }
      return Collections.unmodifiableSet(digests)
    }

  /**
   * Return the a string representation of the OID associated with the
   * encapsulated content info structure carried in the signed data.
   *
   * @return the OID for the content type.
   */
  val signedContentTypeOID: String
    get() = signedData.encapContentInfo.contentType.id

  /**
   * return the ContentInfo
   */
  fun toASN1Structure(): ContentInfo {
    return contentInfo
  }

  /**
   * return the ASN.1 encoded representation of this object.
   */
  @Throws(IOException::class)
  override fun getEncoded(): ByteArray {
    return contentInfo.encoded
  }

  /**
   * return the ASN.1 encoded representation of this object using the specified encoding.
   *
   * @param encoding the ASN.1 encoding format to use ("BER", "DL", or "DER").
   */
  @Throws(IOException::class)
  fun getEncoded(encoding: String?): ByteArray {
    return contentInfo.getEncoded(encoding)
  }
  /**
   * Verify all the SignerInformation objects and optionally their associated counter signatures attached
   * to this CMS SignedData object.
   *
   * @param verifierProvider  a provider of SignerInformationVerifier objects.
   * @param ignoreCounterSignatures if true don't check counter signatures. If false check counter signatures as well.
   * @return true if all verify, false otherwise.
   * @throws CMSException  if an exception occurs during the verification process.
   */
  /**
   * Verify all the SignerInformation objects and their associated counter signatures attached
   * to this CMS SignedData object.
   *
   * @param verifierProvider  a provider of SignerInformationVerifier objects.
   * @return true if all verify, false otherwise.
   * @throws CMSException  if an exception occurs during the verification process.
   */
  @JvmOverloads
  @Throws(CMSException::class)
  fun verifySignatures(verifierProvider: SignerInformationVerifierProvider, ignoreCounterSignatures: Boolean = false): Boolean {
    val signers: Collection<*> = signerInfos!!.signers
    val it = signers.iterator()
    while (it.hasNext()) {
      val signer = it.next() as SignerInformation
      try {
        val verifier = verifierProvider[signer.sID]
        if (!signer.verify(verifier)) {
          return false
        }
        if (!ignoreCounterSignatures) {
          val counterSigners: Collection<*> = signer.getCounterSignatures().signers
          val cIt = counterSigners.iterator()
          while (cIt.hasNext()) {
            if (!verifyCounterSignature(cIt.next() as SignerInformation, verifierProvider)) {
              return false
            }
          }
        }
      } catch (e: OperatorCreationException) {
        throw CMSException("failure in verifier provider: " + e.message, e)
      }
    }
    return true
  }

  @Throws(OperatorCreationException::class, CMSException::class)
  private fun verifyCounterSignature(counterSigner: SignerInformation, verifierProvider: SignerInformationVerifierProvider): Boolean {
    val counterVerifier = verifierProvider[counterSigner.sID]
    if (!counterSigner.verify(counterVerifier)) {
      return false
    }
    val counterSigners = counterSigner.getCounterSignatures().signers
    val cIt = counterSigners.iterator()
    while (cIt.hasNext()) {
      if (!verifyCounterSignature(cIt.next() as SignerInformation, verifierProvider)) {
        return false
      }
    }
    return true
  }

  companion object {
    private val HELPER = CMSSignedHelper.INSTANCE
    private val dgstAlgFinder = DefaultDigestAlgorithmIdentifierFinder()

    /**
     * Return a new CMSSignedData which guarantees to have the passed in digestAlgorithm
     * in it.
     *
     * @param signedData the signed data object to be used as a base.
     * @param digestAlgorithm the digest algorithm to be added to the signed data.
     * @return a new signed data object.
     */
    fun addDigestAlgorithm(
      signedData: CMSSignedData,
      digestAlgorithm: AlgorithmIdentifier
    ): CMSSignedData {
      val digestAlgorithms = signedData.digestAlgorithmIDs
      val digestAlg = CMSSignedHelper.INSTANCE.fixDigestAlgID(digestAlgorithm, dgstAlgFinder)

      //
      // if the algorithm is already present there is no need to add it.
      //
      if (digestAlgorithms.contains(digestAlg)) {
        return signedData
      }

      //
      // copy
      //
      val cms = CMSSignedData(signedData)

      //
      // build up the new set
      //
      val digestAlgs: MutableSet<AlgorithmIdentifier> = HashSet()
      val it: Iterator<*> = digestAlgorithms.iterator()
      while (it.hasNext()) {
        digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(it.next() as AlgorithmIdentifier, dgstAlgFinder))
      }
      digestAlgs.add(digestAlg)
      val digests = CMSUtils.convertToBERSet(digestAlgs)
      val sD = signedData.signedData.toASN1Primitive() as ASN1Sequence
      val vec = ASN1EncodableVector()

      //
      // signers are the last item in the sequence.
      //
      vec.add(sD.getObjectAt(0)) // version
      vec.add(digests)
      for (i in 2 until sD.size()) {
        vec.add(sD.getObjectAt(i))
      }
      cms.signedData = SignedData.getInstance(BERSequence(vec))

      //
      // replace the contentInfo with the new one
      //
      cms.contentInfo = ContentInfo(cms.contentInfo.contentType, cms.signedData)
      return cms
    }

    /**
     * Replace the SignerInformation store associated with this
     * CMSSignedData object with the new one passed in. You would
     * probably only want to do this if you wanted to change the unsigned
     * attributes associated with a signer, or perhaps delete one.
     *
     * @param signedData the signed data object to be used as a base.
     * @param signerInformationStore the new signer information store to use.
     * @return a new signed data object.
     */
    fun replaceSigners(
      signedData: CMSSignedData,
      signerInformationStore: SignerInformationStore
    ): CMSSignedData {
      //
      // copy
      //
      val cms = CMSSignedData(signedData)

      //
      // replace the store
      //
      cms.signerInfoStore = signerInformationStore

      //
      // replace the signers in the SignedData object
      //
      val digestAlgs: MutableSet<AlgorithmIdentifier> = HashSet()
      var vec = ASN1EncodableVector()
      val it: Iterator<*> = signerInformationStore.signers.iterator()
      while (it.hasNext()) {
        val signer = it.next() as SignerInformation
        CMSUtils.addDigestAlgs(digestAlgs, signer, dgstAlgFinder)
        vec.add(signer.toASN1Structure())
      }
      val digests = CMSUtils.convertToBERSet(digestAlgs)
      val signers: ASN1Set = DLSet(vec)
      val sD = signedData.signedData.toASN1Primitive() as ASN1Sequence
      vec = ASN1EncodableVector()

      //
      // signers are the last item in the sequence.
      //
      vec.add(sD.getObjectAt(0)) // version
      vec.add(digests)
      for (i in 2 until sD.size() - 1) {
        vec.add(sD.getObjectAt(i))
      }
      vec.add(signers)
      cms.signedData = SignedData.getInstance(BERSequence(vec))

      //
      // replace the contentInfo with the new one
      //
      cms.contentInfo = ContentInfo(cms.contentInfo.contentType, cms.signedData)
      return cms
    }

    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     *
     * @param signedData the signed data object to be used as a base.
     * @param certificates the new certificates to be used.
     * @param attrCerts the new attribute certificates to be used.
     * @param revocations the new CRLs to be used - a collection of X509CRLHolder objects, OtherRevocationInfoFormat, or both.
     * @return a new signed data object.
     * @exception CMSException if there is an error processing the CertStore
     */
    @Throws(CMSException::class)
    fun replaceCertificatesAndCRLs(
      signedData: CMSSignedData,
      certificates: Store<X509CertificateHolder>?,
      attrCerts: Store<X509AttributeCertificateHolder>?,
      revocations: Store<X509CRLHolder>?
    ): CMSSignedData {
      //
      // copy
      //
      val cms = CMSSignedData(signedData)

      //
      // replace the certs and revocations in the SignedData object
      //
      var certSet: ASN1Set? = null
      var crlSet: ASN1Set? = null
      if (certificates != null || attrCerts != null) {
        val certs = mutableListOf<Any>()
        if (certificates != null) {
          certs.addAll(CMSUtils.getCertificatesFromStore(certificates))
        }
        if (attrCerts != null) {
          certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts))
        }
        val set = CMSUtils.createBerSetFromList(certs)
        if (set.size() != 0) {
          certSet = set
        }
      }
      if (revocations != null) {
        val set = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(revocations))
        if (set.size() != 0) {
          crlSet = set
        }
      }

      //
      // replace the CMS structure.
      //
      cms.signedData = SignedData(
        signedData.signedData.digestAlgorithms,
        signedData.signedData.encapContentInfo,
        certSet,
        crlSet,
        signedData.signedData.signerInfos
      )

      //
      // replace the contentInfo with the new one
      //
      cms.contentInfo = ContentInfo(cms.contentInfo.contentType, cms.signedData)
      return cms
    }
  }
}