package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData
import com.jetbrains.signatureverifier.crypt.*
import com.jetbrains.signatureverifier.crypt.OIDs.SPC_INDIRECT_DATA
import com.jetbrains.signatureverifier.crypt.OIDs.SPC_SIPINFO_OBJID
import com.jetbrains.signatureverifier.powershell.PowershellScriptFile
import com.jetbrains.util.TestUtil.getTestByteChannel
import com.jetbrains.util.TestUtil.getTestDataInputStream
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.util.Selector
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.stream.Stream

class PowerShellSignatureVerifierTests {
  private val simpleVerificationParams =
    SignatureVerificationParams(null, null, buildChain = false, withRevocationCheck = false)

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(resourceName: String, expectedResult: VerifySignatureStatus) {
    val result = getTestByteChannel("powershell", resourceName).use {
      val psFile = PowershellScriptFile(it)
      val signatureData = psFile.GetSignatureData()
      if (signatureData.IsEmpty) {
        return@use VerifySignatureResult(VerifySignatureStatus.InvalidSignature)
      }

      val signedMessage = SignedMessage.CreateInstance(signatureData)
      try {
        verifyContentHash(signedMessage.SignedData, psFile)
      } catch (ex: VerificationException) {
        return@use VerifySignatureResult(VerifySignatureStatus.InvalidSignature, ex.message)
      }

      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, simpleVerificationParams) }
    }
    assertEquals(expectedResult, result.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  fun VerifySignWithChainTest(
    resourceName: String,
    expectedResult: VerifySignatureStatus,
  ) {
    val result = getTestDataInputStream("powershell", resourceName).use {
      val file = PowershellScriptFile(it)
      val signatureData = file.GetSignatureData()
      if (signatureData.IsEmpty) {
        return@use VerifySignatureResult(VerifySignatureStatus.InvalidSignature)
      }

      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, chainVerificationParams) }
    }

    assertEquals(expectedResult, result.Status)
  }

  class VerificationException(msg: String?) : Exception(msg)

  fun verifyContentHash(
    signedData: CMSSignedData,
    file: PowershellScriptFile
  ) {
    if (signedData.digestAlgorithmIDs.size != 1) {
      throw VerificationException("Signed Data must contain exactly one DigestAlgorithm, got: ${signedData.digestAlgorithmIDs}")
    }

    val signedDataAlgorithm = signedData.digestAlgorithmIDs.first().algorithm

    if (signedDataAlgorithm !in digests.keys) {
      val supported = digests.keys.joinToString(", ")
      throw VerificationException("Signed Data algorithm is not supported: $signedDataAlgorithm. Supported algorithms: $supported")
    }

    val signedData1: SignedData = SignedData.getInstance(signedData.toASN1Structure().content)
    val contentInfo: ContentInfo = signedData1.encapContentInfo

    val digestInfo: DigestInfo = getSpcIndirectDataContent(contentInfo)
      ?: throw VerificationException("Signed Data does not contain SpcIndirectData structure ($SPC_INDIRECT_DATA) with DigestInfo")

    // Check that SpcIndirectContent DigestAlgorithm equals CMSSignedData algorithm
    if (digestInfo.algorithmId.algorithm != signedDataAlgorithm) {
      throw VerificationException("Signed Data algorithm does not match with spcDigestAlgorithm")
    }

    // Check that SignerInfo DigestAlgorithm equals CMSSignedData algorithm
    if (signedData.signerInfos.size() != 1) {
      throw VerificationException("Signed Data must contain exactly one SignerInfo. Got: ${signedData.signerInfos.toList()}")
    }

    val signerInformation = signedData.signerInfos.first()
    if (signerInformation.digestAlgorithmID.algorithm != signedDataAlgorithm) {
      throw VerificationException("Signed Data algorithm doesn't match with SignerInformation algorithm")
    }

    // #2 Check the embedded hash in spcIndirectContent matches with the computed hash of the pefile
    if (!file.ComputeHash(digests[signedDataAlgorithm]!!).contentEquals(digestInfo.digest)) {
      throw VerificationException("The embedded hash in the SignedData is not equal to the computed hash")
    }

    // #3 The hash of the spc blob should be equal to message digest in authenticated attributes of signed data
    // Get the message digest from authenticated attributes, see authenticode_pe documentation
    val messageDigestInAuthenticatedAttr: ByteArray
    val attribute: Attribute? = signerInformation.signedAttributes?.get(CMSAttributes.messageDigest)
    val digestObj: Any? = attribute?.attrValues?.first()

    if (digestObj is ASN1OctetString) {
      messageDigestInAuthenticatedAttr = digestObj.octets
    } else {
      throw VerificationException("No message digest was found in authenticated attributes")
    }

    // Get the spc blob
    val spcBlob: ByteArray = getSpcBlob(contentInfo.content.toASN1Primitive())
      ?: throw VerificationException("No SpcIndirectData structure was found in SignedData")

    // Calculate the digest of the spcblob
    val spcDigest = digest(signedDataAlgorithm, spcBlob)

    // Compare both
    if (!messageDigestInAuthenticatedAttr.contentEquals(spcDigest)) {
      throw VerificationException("The hash of stripped content of SpcInfo does not match digest found in authenticated attributes")
    }

    // #4 Check the hash in Authenticated Attributes with Encrypted Hash
    @Suppress("UNCHECKED_CAST")
    val holder: X509CertificateHolder =
      signedData.certificates.getMatches(signerInformation.sID as Selector<X509CertificateHolder?>)
        .first() as X509CertificateHolder
    val certificate: X509Certificate = try {
      JcaX509CertificateConverter().getCertificate(holder)
    } catch (e: CertificateException) {
      throw VerificationException(e.message)
    }
    JcaSignerInfoVerifierBuilder(JcaDigestCalculatorProviderBuilder().build()).build(certificate)
    val key: PublicKey = certificate.publicKey
    val signature: Signature
    try {
      val signerInfo = signerInformation.toASN1Structure()
      val digestAndEncryptionAlgorithmName = DefaultCMSSignatureAlgorithmNameGenerator().getSignatureName(
        signerInformation.digestAlgorithmID,
        signerInfo.digestEncryptionAlgorithm
      )
      signature = Signature.getInstance(digestAndEncryptionAlgorithmName)
    } catch (e: NoSuchAlgorithmException) {
      throw VerificationException(e.message)
    }
    try {
      signature.initVerify(key)
    } catch (e: InvalidKeyException) {
      throw VerificationException(e.message)
    }

    try {
      signature.update(signerInformation.getEncodedSignedAttributes())
      if (!signature.verify(signerInformation.getSignature())) {
        throw VerificationException("The hash in the the authenticated attributes doesn't match the encrypted hash(getSignature())")
      }
      //Note that the getSignature() method returns the encrypted hash in the SignerInformation
    } catch (e: SignatureException) {
      throw VerificationException(e.message)
    }

    //#4 Check the countersigner hash
    if (signerInformation.getCounterSignatures().size() != 0) {
      val counterSignerInformation = signerInformation.getCounterSignatures().first()

      val authAttrHash = digest(counterSignerInformation.digestAlgorithmID.algorithm, signerInformation.getSignature())

      val messageDigestInCounterSignature: ByteArray
      val attributeOfCounterSignature: Attribute? =
        counterSignerInformation.signedAttributes?.get(CMSAttributes.messageDigest)
      val digestObjOfCounterSignature: Any? = attributeOfCounterSignature?.attrValues?.first()

      if (digestObjOfCounterSignature is ASN1OctetString) {
        messageDigestInCounterSignature = digestObjOfCounterSignature.octets
      } else {
        throw VerificationException("No message digest was found in authenticated attributes of counter signature")
      }

      //Compare both and throw exception if not equal
      if (!messageDigestInCounterSignature.contentEquals(authAttrHash)) {
        throw VerificationException("The digest of encrypted hash in the signerInformation does not match with digest found in counter signature")
      }
    }
  }

  private fun digest(
    algorithm: ASN1ObjectIdentifier,
    blob: ByteArray
  ): ByteArray {
    if (algorithm !in digests.keys) {
      val supported = digests.keys.joinToString(", ")
      throw VerificationException("Algorithm is not supported: $algorithm. Supported algorithms: $supported")
    }

    val md: MessageDigest
    try {
      md = MessageDigest.getInstance(digests[algorithm]!!)
    } catch (e: NoSuchAlgorithmException) {
      throw VerificationException(e.message)
    }
    md.update(blob)
    val digest = md.digest()
    return digest
  }

  @OptIn(ExperimentalStdlibApi::class)
  fun getSpcBlob(primitive: ASN1Primitive): ByteArray? {
    val outputStream = ByteArrayOutputStream()
    if (primitive is ASN1Sequence) {
      val it = primitive.iterator()
      while (it.hasNext()) {
        val p: ASN1Primitive = it.next() as ASN1Primitive
        outputStream.write(p.getEncoded())
      }
      val array = outputStream.toByteArray()
//      require(array.contentEquals(primitive.encoded)) {
//        "Expected array content to match primitive encoding:\nPrimitive.encoded: ${primitive.encoded.toHexString()}\nSequence.encoded: ${array.toHexString()}"
//      }
      return array
    }
    return null
  }

  private val digests = mapOf<ASN1ObjectIdentifier, String>(
    TSPAlgorithms.MD5 to "MD5",
    TSPAlgorithms.SHA1 to "SHA-1",
    TSPAlgorithms.SHA256 to "SHA-256",
    TSPAlgorithms.SHA384 to "SHA-384",
    TSPAlgorithms.SHA512 to "SHA-512",
  )


  // See SpcIndirectDataToken.cs
  private fun getSpcIndirectDataContent(contentInfo: ContentInfo): DigestInfo? {
    if (SPC_INDIRECT_DATA == contentInfo.contentType) {
      val obj = contentInfo.content.toASN1Primitive()

      if (obj is ASN1Sequence) {
        val sequences = obj.objects.toList().filterIsInstance<ASN1Sequence>()
        require(sequences.size == 2) {}
        require(SPC_SIPINFO_OBJID == sequences[0].objects.nextElement())
        return DigestInfo.getInstance(sequences[1])
      }
    }
    return null
  }

  private val chainVerificationParams by lazy {
    getTestDataInputStream("powershell", DIGICERT_ROOT_G4).use { codesignroots ->
      getTestDataInputStream("powershell", DIGICERT_ROOT_G4).use { timestamproots ->
        SignatureVerificationParams(
          codesignroots, timestamproots, buildChain = true, withRevocationCheck = false
        ).apply {
          this.RootCertificates // read streams
        }
      }
    }
  }

  companion object {
    private const val DIGICERT_ROOT_G4 = "DigiCertTrustedRootG4.crt.pem"

    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        // unsigned
        Arguments.of("script-utf-8-no-bom-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-no-bom-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-bom-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-bom-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16be-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16be-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16le-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16le-lf.ps1", VerifySignatureStatus.InvalidSignature),

        // signed
        Arguments.of("signed-script-utf-8-no-bom-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-no-bom-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-bom-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-bom-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16be-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16be-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16le-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16le-lf.ps1", VerifySignatureStatus.Valid),

        // signed and then edited
        Arguments.of("corrupted-script-utf-16le-crlf.ps1", VerifySignatureStatus.InvalidSignature),

        )
    }

    @JvmStatic
    fun VerifySignWithChainTestProvider(): Stream<Arguments> {
      return Stream.of(
        // unsigned
        Arguments.of("script-utf-8-no-bom-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-no-bom-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-bom-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-8-bom-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16be-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16be-lf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16le-crlf.ps1", VerifySignatureStatus.InvalidSignature),
        Arguments.of("script-utf-16le-lf.ps1", VerifySignatureStatus.InvalidSignature),
        // signed
        Arguments.of("signed-script-utf-8-no-bom-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-no-bom-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-bom-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-8-bom-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16be-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16be-lf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16le-crlf.ps1", VerifySignatureStatus.Valid),
        Arguments.of("signed-script-utf-16le-lf.ps1", VerifySignatureStatus.Valid),
      )
    }
  }
}
