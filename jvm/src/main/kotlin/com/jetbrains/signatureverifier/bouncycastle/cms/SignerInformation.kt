package com.jetbrains.signatureverifier.bouncycastle.cms

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessable
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignerDigestMismatchException
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException
import org.bouncycastle.cms.SignerId
import org.bouncycastle.cms.SignerInformationVerifier
import org.bouncycastle.operator.ContentVerifier
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.RawContentVerifier
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.io.TeeOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.*

/**
 * an expanded SignerInfo block from a CMS Signed message
 */
class SignerInformation {
  val sID: SignerId
  private var content: CMSProcessable?
  private var signature: ByteArray
  var contentType: ASN1ObjectIdentifier?
  var isCounterSignature: Boolean

  // Derived
  private var signedAttributeValues: AttributeTable? = null
  private var unsignedAttributeValues: AttributeTable? = null
  private var resultDigest: ByteArray?
  protected val info: SignerInfo
  val digestAlgorithmID: AlgorithmIdentifier
  var encryptionAlgorithm: AlgorithmIdentifier
  protected var signedAttributeSet: ASN1Set?
  protected var unsignedAttributeSet: ASN1Set?

  internal constructor(
    info: SignerInfo,
    contentType: ASN1ObjectIdentifier?,
    content: CMSProcessable?,
    resultDigest: ByteArray?
  ) {
    this.info = info
    this.contentType = contentType
    isCounterSignature = contentType == null
    val s = info.sid
    if (s.isTagged) {
      val octs = ASN1OctetString.getInstance(s.id)
      sID = SignerId(octs.octets)
    } else {
      val iAnds = IssuerAndSerialNumber.getInstance(s.id)
      sID = SignerId(iAnds.name, iAnds.serialNumber.value)
    }
    digestAlgorithmID = info.digestAlgorithm
    signedAttributeSet = info.authenticatedAttributes
    unsignedAttributeSet = info.unauthenticatedAttributes
    encryptionAlgorithm = info.digestEncryptionAlgorithm
    signature = info.encryptedDigest.octets
    this.content = content
    this.resultDigest = resultDigest
  }

  /**
   * Protected constructor. In some cases clients have their own idea about how to encode
   * the signed attributes and calculate the signature. This constructor is to allow developers
   * to deal with that by extending off the class and overriding methods like getSignedAttributes().
   *
   * @param baseInfo the SignerInformation to base this one on.
   */
  protected   constructor(baseInfo: SignerInformation)
    : this(baseInfo, baseInfo.info) {
  }

  /**
   * Protected constructor. In some cases clients also have their own ideas about what
   * goes in various SignerInfo fields. This constructor is to allow developers to deal with
   * that by also tweaking the SignerInfo so that these issues can be dealt with.
   *
   * @param baseInfo the SignerInformation to base this one on.
   * @param info     the SignerInfo to associate with the existing baseInfo data.
   */
  protected constructor(baseInfo: SignerInformation, info: SignerInfo) {
    this.info = info
    contentType = baseInfo.contentType
    isCounterSignature = baseInfo.isCounterSignature
    this.sID = baseInfo.sID
    this.digestAlgorithmID = info.digestAlgorithm
    signedAttributeSet = info.authenticatedAttributes
    unsignedAttributeSet = info.unauthenticatedAttributes
    encryptionAlgorithm = info.digestEncryptionAlgorithm
    signature = info.encryptedDigest.octets
    content = baseInfo.content
    resultDigest = baseInfo.resultDigest
    signedAttributeValues = signedAttributes
    unsignedAttributeValues = unsignedAttributes
  }

  @Throws(IOException::class)
  private fun encodeObj(
    obj: ASN1Encodable?
  ): ByteArray? {
    return obj?.toASN1Primitive()?.encoded
  }

  /**
   * return the version number for this objects underlying SignerInfo structure.
   */
  val version: Int
    get() = info.version.intValueExact()

  /**
   * return the object identifier for the signature.
   */
  val digestAlgOID: String
    get() = digestAlgorithmID.algorithm.id

  /**
   * return the signature parameters, or null if there aren't any.
   */
  val digestAlgParams: ByteArray?
    get() = try {
      encodeObj(digestAlgorithmID.parameters)
    } catch (e: Exception) {
      throw RuntimeException("exception getting digest parameters $e")
    }

  /**
   * return the content digest that was calculated during verification.
   */
  val contentDigest: ByteArray
    get() {
      checkNotNull(resultDigest) { "method can only be called after verify." }
      return Arrays.clone(resultDigest)
    }

  /**
   * return the object identifier for the signature.
   */
  val encryptionAlgOID: String
    get() = encryptionAlgorithm.algorithm.id

  /**
   * return the signature/encryption algorithm parameters, or null if
   * there aren't any.
   */
  val encryptionAlgParams: ByteArray?
    get() = try {
      encodeObj(encryptionAlgorithm.parameters)
    } catch (e: Exception) {
      throw RuntimeException("exception getting encryption parameters $e")
    }

  /**
   * return a table of the signed attributes - indexed by
   * the OID of the attribute.
   */
  val signedAttributes: AttributeTable?
    get() {
      if (signedAttributeSet != null && signedAttributeValues == null) {
        signedAttributeValues = AttributeTable(signedAttributeSet)
      }
      return signedAttributeValues
    }

  /**
   * return a table of the unsigned attributes indexed by
   * the OID of the attribute.
   */
  val unsignedAttributes: AttributeTable?
    get() {
      if (unsignedAttributeSet != null && unsignedAttributeValues == null) {
        unsignedAttributeValues = AttributeTable(unsignedAttributeSet)
      }
      return unsignedAttributeValues
    }

  /**
   * return the encoded signature
   */
  fun getSignature(): ByteArray {
    return Arrays.clone(signature)
  }

  /**
   * Return a SignerInformationStore containing the counter signatures attached to this
   * signer. If no counter signatures are present an empty store is returned.
   */
  fun getCounterSignatures(): SignerInformationStore {
    // TODO There are several checks implied by the RFC3852 comments that are missing

    /*
        The countersignature attribute MUST be an unsigned attribute; it MUST
        NOT be a signed attribute, an authenticated attribute, an
        unauthenticated attribute, or an unprotected attribute.
        */
    val unsignedAttributeTable: AttributeTable = unsignedAttributes ?: return SignerInformationStore(listOf())
    val counterSignatures = mutableListOf<SignerInformation>()

    /*
        The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
        UnsignedAttributes in a signerInfo may include multiple instances of
        the countersignature attribute.
        */
    val allCSAttrs = unsignedAttributeTable.getAll(CMSAttributes.counterSignature)
    for (i in 0 until allCSAttrs.size()) {
      val counterSignatureAttribute = allCSAttrs[i] as Attribute

      /*
      A countersignature attribute can have multiple attribute values.  The
      syntax is defined as a SET OF AttributeValue, and there MUST be one
      or more instances of AttributeValue present.
      */
      val values = counterSignatureAttribute.attrValues
      if (values.size() < 1) {
        // TODO Throw an appropriate exception?
      }
      val en = values.objects
      while (en.hasMoreElements()) {
        /*
        Countersignature values have the same meaning as SignerInfo values
        for ordinary signatures, except that:

           1. The signedAttributes field MUST NOT contain a content-type
              attribute; there is no content type for countersignatures.

           2. The signedAttributes field MUST contain a message-digest
              attribute if it contains any other attributes.

           3. The input to the message-digesting process is the contents
              octets of the DER encoding of the signatureValue field of the
              SignerInfo value with which the attribute is associated.
        */
        val si = SignerInfo.getInstance(en.nextElement())
        counterSignatures.add(SignerInformation(si, null, CMSProcessableByteArray(getSignature()), null))
      }
    }
    return SignerInformationStore(counterSignatures)
  }

  /**
   * return the BER (!!) encoding of the signed attributes.
   *
   * @throws IOException if an encoding error occurs.
   */
  @Throws(IOException::class)
  fun getEncodedSignedAttributes(): ByteArray? {
    return signedAttributeSet?.getEncoded(ASN1Encoding.BER)
  }

  @Throws(CMSException::class)
  private fun doVerify(
    verifier: SignerInformationVerifier
  ): Boolean {
    val encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(encryptionAlgOID)
    val contentVerifier: ContentVerifier
    contentVerifier = try {
      verifier.getContentVerifier(encryptionAlgorithm, info.digestAlgorithm)
    } catch (e: OperatorCreationException) {
      throw CMSException("can't create content verifier: " + e.message, e)
    }
    try {
      val sigOut = contentVerifier.outputStream
      if (resultDigest == null) {
        val calc = verifier.getDigestCalculator(digestAlgorithmID)
        if (content != null) {
          val digOut = calc.outputStream
          if (signedAttributeSet == null) {
            if (contentVerifier is RawContentVerifier) {
              content!!.write(digOut)
            } else {
              val cOut: OutputStream = TeeOutputStream(digOut, sigOut)
              content!!.write(cOut)
              cOut.close()
            }
          } else {
            content!!.write(digOut)
            sigOut.write(getEncodedSignedAttributes())
          }
          digOut.close()
        } else if (signedAttributeSet != null) {
          sigOut.write(getEncodedSignedAttributes())
        } else {
          // TODO Get rid of this exception and just treat content==null as empty not missing?
          throw CMSException("data not encapsulated in signature - use detached constructor.")
        }
        resultDigest = calc.digest
      } else {
        if (signedAttributeSet == null) {
          content?.write(sigOut)
        } else {
          sigOut.write(getEncodedSignedAttributes())
        }
      }
      sigOut.close()
    } catch (e: IOException) {
      throw CMSException("can't process mime object to create signature.", e)
    } catch (e: OperatorCreationException) {
      throw CMSException("can't create digest calculator: " + e.message, e)
    }

    // RFC 3852 11.1 Check the content-type attribute is correct
    verifyContentTypeAttributeValue()
    val signedAttrTable = signedAttributes

    // RFC 6211 Validate Algorithm Identifier protection attribute if present
    verifyAlgorithmIdentifierProtectionAttribute(signedAttrTable)

    // RFC 3852 11.2 Check the message-digest attribute is correct
    verifyMessageDigestAttribute()

    // RFC 3852 11.4 Validate countersignature attribute(s)
    verifyCounterSignatureAttribute(signedAttrTable)
    return try {
      if (signedAttributeSet == null && resultDigest != null) {
        if (contentVerifier is RawContentVerifier) {
          val rawVerifier = contentVerifier as RawContentVerifier
          if (encName == "RSA") {
            val digInfo = DigestInfo(AlgorithmIdentifier(digestAlgorithmID.algorithm, DERNull.INSTANCE), resultDigest)
            return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), getSignature())
          }
          return rawVerifier.verify(resultDigest, getSignature())
        }
      }
      contentVerifier.verify(getSignature())
    } catch (e: IOException) {
      throw CMSException("can't process mime object to create signature.", e)
    }
  }

  /**
   * RFC 3852 11.1 Check the content-type attribute is correct
   *
   * @throws CMSException when content-type was invalid.
   */
  @Throws(CMSException::class)
  private fun verifyContentTypeAttributeValue() {
    val validContentType = getSingleValuedSignedAttribute(
      CMSAttributes.contentType, "content-type"
    )
    if (validContentType == null) {
      if (!isCounterSignature && signedAttributeSet != null) {
        throw CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data")
      }
    } else {
      /*
                    * We do not care !
          * https://github.com/bcgit/bc-csharp/issues/312
                    */

      //if (isCounterSignature) {
      //  throw CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute")
      //}
      //if (validContentType !is ASN1ObjectIdentifier) {
      //  throw CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'")
      //}
      //if (!validContentType.equals(contentType)) {
      //  throw CMSException("content-type attribute value does not match eContentType")
      //}
    }
  }

  /**
   * RFC 3852 11.2 Check the message-digest attribute is correct
   *
   * @throws CMSException when message-digest attribute was rejected
   */
  @Throws(CMSException::class)
  private fun verifyMessageDigestAttribute() {
    val validMessageDigest = getSingleValuedSignedAttribute(
      CMSAttributes.messageDigest, "message-digest"
    )
    if (validMessageDigest == null) {
      if (signedAttributeSet != null) {
        throw CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present")
      }
    } else {
      if (validMessageDigest !is ASN1OctetString) {
        throw CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'")
      }
      if (!Arrays.constantTimeAreEqual(resultDigest, validMessageDigest.octets)) {
        throw CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value")
      }
    }
  }

  /**
   * RFC 6211 Validate Algorithm Identifier protection attribute if present
   *
   * @param signedAttrTable signed attributes
   * @throws CMSException when cmsAlgorihmProtect attribute was rejected
   */
  @Throws(CMSException::class)
  private fun verifyAlgorithmIdentifierProtectionAttribute(signedAttrTable: AttributeTable?) {
    val unsignedAttrTable = unsignedAttributes
    if (unsignedAttrTable != null && unsignedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect).size() > 0) {
      throw CMSException("A cmsAlgorithmProtect attribute MUST be a signed attribute")
    }
    if (signedAttrTable != null) {
      val protectionAttributes = signedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect)
      if (protectionAttributes.size() > 1) {
        throw CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present")
      }
      if (protectionAttributes.size() > 0) {
        val attr = Attribute.getInstance(protectionAttributes[0])
        if (attr.attrValues.size() != 1) {
          throw CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value")
        }
        val algorithmProtection = CMSAlgorithmProtection.getInstance(attr.attributeValues[0])
        if (!CMSUtils.isEquivalent(algorithmProtection.digestAlgorithm, info.digestAlgorithm)) {
          throw CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm")
        }
        if (!CMSUtils.isEquivalent(algorithmProtection.signatureAlgorithm, info.digestEncryptionAlgorithm)) {
          throw CMSException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm")
        }
      }
    }
  }

  /**
   * RFC 3852 11.4 Validate countersignature attribute(s)
   *
   * @param signedAttrTable signed attributes
   * @throws CMSException when countersignature attribute was rejected
   */
  @Throws(CMSException::class)
  private fun verifyCounterSignatureAttribute(signedAttrTable: AttributeTable?) {
    if (signedAttrTable != null
      && signedAttrTable.getAll(CMSAttributes.counterSignature).size() > 0
    ) {
      throw CMSException("A countersignature attribute MUST NOT be a signed attribute")
    }
    val unsignedAttrTable = unsignedAttributes
    if (unsignedAttrTable != null) {
      val csAttrs = unsignedAttrTable.getAll(CMSAttributes.counterSignature)
      for (i in 0 until csAttrs.size()) {
        val csAttr = Attribute.getInstance(csAttrs[i])
        if (csAttr.attrValues.size() < 1) {
          throw CMSException("A countersignature attribute MUST contain at least one AttributeValue")
        }

        // Note: We don't recursively validate the countersignature value
      }
    }
  }

  /**
   * Verify that the given verifier can successfully verify the signature on
   * this SignerInformation object.
   *
   * @param verifier a suitably configured SignerInformationVerifier.
   * @return true if the signer information is verified, false otherwise.
   * @throws org.bouncycastle.cms.CMSVerifierCertificateNotValidException if the provider has an associated certificate and the certificate is not valid at the time given as the SignerInfo's signing time.
   * @throws org.bouncycastle.cms.CMSException if the verifier is unable to create a ContentVerifiers or DigestCalculators.
   */
  @Throws(CMSException::class)
  fun verify(verifier: SignerInformationVerifier): Boolean {
    val signingTime = getSigningTime() // has to be validated if present.
    if (verifier.hasAssociatedCertificate()) {
      if (signingTime != null) {
        val dcv = verifier.associatedCertificate
        if (!dcv.isValidOn(signingTime.date)) {
          throw CMSVerifierCertificateNotValidException("verifier not valid at signingTime")
        }
      }
    }
    return doVerify(verifier)
  }

  /**
   * Return the underlying ASN.1 object defining this SignerInformation object.
   *
   * @return a SignerInfo.
   */
  fun toASN1Structure(): SignerInfo {
    return info
  }

  @Throws(CMSException::class)
  private fun getSingleValuedSignedAttribute(
    attrOID: ASN1ObjectIdentifier, printableName: String
  ): ASN1Primitive? {
    val unsignedAttrTable = unsignedAttributes
    if (unsignedAttrTable != null
      && unsignedAttrTable.getAll(attrOID).size() > 0
    ) {
      throw CMSException(
        "The " + printableName
            + " attribute MUST NOT be an unsigned attribute"
      )
    }
    val signedAttrTable = signedAttributes ?: return null
    val v = signedAttrTable.getAll(attrOID)
    return when (v.size()) {
      0 -> null
      1 -> {
        val t = v[0] as Attribute
        val attrValues = t.attrValues
        if (attrValues.size() != 1) {
          throw CMSException(
            "A " + printableName
                + " attribute MUST have a single attribute value"
          )
        }
        attrValues.getObjectAt(0).toASN1Primitive()
      }
      else -> throw CMSException(
        "The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
            + printableName + " attribute"
      )
    }
  }

  @Throws(CMSException::class)
  private fun getSigningTime(): Time? {
    val validSigningTime = getSingleValuedSignedAttribute(
      CMSAttributes.signingTime, "signing-time"
    ) ?: return null
    return try {
      Time.getInstance(validSigningTime)
    } catch (e: IllegalArgumentException) {
      throw CMSException("signing-time attribute value not a valid 'Time' structure")
    }
  }

  companion object {
    /**
     * Return a signer information object with the passed in unsigned
     * attributes replacing the ones that are current associated with
     * the object passed in.
     *
     * @param signerInformation  the signerInfo to be used as the basis.
     * @param unsignedAttributes the unsigned attributes to add.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    fun replaceUnsignedAttributes(
      signerInformation: SignerInformation,
      unsignedAttributes: AttributeTable?
    ): SignerInformation {
      val sInfo = signerInformation.info
      var unsignedAttr: ASN1Set? = null
      if (unsignedAttributes != null) {
        unsignedAttr = DERSet(unsignedAttributes.toASN1EncodableVector())
      }
      return SignerInformation(
        SignerInfo(
          sInfo.sid, sInfo.digestAlgorithm,
          sInfo.authenticatedAttributes, sInfo.digestEncryptionAlgorithm, sInfo.encryptedDigest, unsignedAttr
        ),
        signerInformation.contentType, signerInformation.content, null
      )
    }

    /**
     * Return a signer information object with passed in SignerInformationStore representing counter
     * signatures attached as an unsigned attribute.
     *
     * @param signerInformation the signerInfo to be used as the basis.
     * @param counterSigners    signer info objects carrying counter signature.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    fun addCounterSigners(
      signerInformation: SignerInformation,
      counterSigners: SignerInformationStore
    ): SignerInformation {
      // TODO Perform checks from RFC 3852 11.4
      val sInfo = signerInformation.info
      val unsignedAttr = signerInformation.unsignedAttributes
      val v: ASN1EncodableVector
      v = if (unsignedAttr != null) {
        unsignedAttr.toASN1EncodableVector()
      } else {
        ASN1EncodableVector()
      }
      val sigs = ASN1EncodableVector()
      val it: Iterator<*> = counterSigners.signers.iterator()
      while (it.hasNext()) {
        sigs.add((it.next() as SignerInformation).toASN1Structure())
      }
      v.add(Attribute(CMSAttributes.counterSignature, DERSet(sigs)))
      return SignerInformation(
        SignerInfo(
          sInfo.sid, sInfo.digestAlgorithm,
          sInfo.authenticatedAttributes, sInfo.digestEncryptionAlgorithm, sInfo.encryptedDigest, DERSet(v)
        ),
        signerInformation.contentType, signerInformation.content, null
      )
    }
  }
}