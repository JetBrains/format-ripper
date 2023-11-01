package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.*
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToDate
import com.jetbrains.signatureverifier.tests.authenticode.SpcAttributeOptional
import com.jetbrains.signatureverifier.tests.authenticode.SpcIndirectDataContent
import com.jetbrains.signatureverifier.tests.authenticode.SpcPeImageData
import com.jetbrains.util.ReadToEnd
import com.jetbrains.util.Seek
import com.jetbrains.util.SeekOrigin
import com.jetbrains.util.TestUtil.getTestByteChannelCopy
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.CollectionStore
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.ArgumentMatchers.anyList
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.channels.SeekableByteChannel
import java.security.PrivateKey
import java.time.Clock
import java.time.LocalDateTime
import java.util.*
import java.util.stream.Stream

class FakePkiTest {
  private val localClock = Clock.systemDefaultZone()

  private fun nowPlusDays(days: Long): Date = LocalDateTime.now(localClock).plusDays(days).ConvertToDate()
  private fun nowPlusSeconds(seconds: Long): Date = LocalDateTime.now(localClock).plusSeconds(seconds).ConvertToDate()

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  fun InvalidSignatureNoSignerCert(peResourceName: String) {
    val pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10))

    val (keyPair, cert) = pki.Enroll("sub", nowPlusDays(0), nowPlusDays(9), false)

    getTestByteChannelCopy("pe", peResourceName).use { peStream ->
      signPe(peStream, keyPair.private, cert, false).use { signedPeStream ->
        val peFile = PeFile(signedPeStream)
        val signatureData = peFile.GetSignatureData()
        val signedMessage = SignedMessage.CreateInstance(signatureData)

        getRootStoreStream(pki.Certificate).use { signRootCertStore ->
          val verificationParams = SignatureVerificationParams(signRootCertStore, withRevocationCheck = false)
          val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
          val res = runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

          Assertions.assertEquals(VerifySignatureStatus.InvalidSignature, res.Status)
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  fun InvalidChainCertRevoked(peResourceName: String) {
    val pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10))
    val (keyPair, cert) = pki.Enroll("sub", nowPlusDays(0), nowPlusDays(9), true)

    pki.Revoke(cert, true)
    runBlocking { delay(2000) }

    val crlCache = mock(CrlCacheFileSystem::class.java)
    `when`(crlCache.GetCrls(anyString())).thenReturn(listOf())
    `when`(crlCache.UpdateCrls(anyString(), anyList())).then {}

    val crlSource = mock(CrlSource::class.java)
    runBlocking { `when`(crlSource.GetCrlAsync(anyString())).thenReturn(pki.Crl?.encoded) }

    getTestByteChannelCopy("pe", peResourceName).use { peStream ->
      signPe(peStream, keyPair.private, cert).use { signedPeStream ->
        val peFile = PeFile(signedPeStream)
        val signatureData = peFile.GetSignatureData()
        val signedMessage = SignedMessage.CreateInstance(signatureData)

        getRootStoreStream(pki.Certificate).use { signRootCertStore ->
          val verificationParams = SignatureVerificationParams(signRootCertStore)
          val signedMessageVerifier =
            SignedMessageVerifier(CrlProvider(crlSource, crlCache, ConsoleLogger.Instance), ConsoleLogger.Instance)
          val res = runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

          Assertions.assertEquals(VerifySignatureStatus.InvalidChain, res.Status)
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  fun InvalidChainCertOutdated(peResourceName: String) {
    val pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10))
    val (keyPair, cert) = pki.Enroll("sub", nowPlusDays(0), nowPlusSeconds(1), false)

    runBlocking { delay(2000) }

    getTestByteChannelCopy("pe", peResourceName).use { peStream ->
      signPe(peStream, keyPair.private, cert).use { signedPeStream ->
        val peFile = PeFile(signedPeStream)
        val signatureData = peFile.GetSignatureData()
        val signedMessage = SignedMessage.CreateInstance(signatureData)
        val verificationParams = SignatureVerificationParams(buildChain = false)
        val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)

        val res = runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

        Assertions.assertEquals(VerifySignatureStatus.InvalidSignature, res.Status)
      }
    }
  }

  private fun signPe(
    peStream: SeekableByteChannel,
    privateKey: PrivateKey,
    cert: X509CertificateHolder,
    addSignerCert: Boolean = true
  ): SeekableByteChannel {
    val cmsGen = CMSSignedDataGenerator()
    val sha1Signer = JcaContentSignerBuilder("SHA1withRSA").build(privateKey)

    cmsGen.addSignerInfoGenerator(
      JcaSignerInfoGeneratorBuilder(
        JcaDigestCalculatorProviderBuilder()
          .build()
      )
        .build(sha1Signer, cert)
    )

    if (addSignerCert)
      cmsGen.addCertificates(CollectionStore(listOf(cert)))

    val peFile = PeFile(peStream)
    val content = createCmsSignedData(peFile)
    val contentData = content.toASN1Primitive().encoded
    val cmsSignedData = cmsGen.generate(CMSProcessableByteArray(contentData), true)

    peStream.Seek(0, SeekOrigin.Begin)
    val signedPeStream = SeekableInMemoryByteChannel(peStream.ReadToEnd())
    val writer = BinaryWriter(signedPeStream)
    val encodedCmsSignedData = cmsSignedData.encoded
    signedPeStream.Seek(0, SeekOrigin.End)
    val attributeCertificateTableOffset = signedPeStream.position()
    //write attribute certificate table
    writer.Write(encodedCmsSignedData.count())  //dwLength
    writer.Write(0x0200.toShort())              //wRevision = WIN_CERT_REVISION_2_0
    writer.Write(2.toShort())                   //wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    writer.Write(encodedCmsSignedData)          //bCertificate

    //write new ImageDirectoryEntrySecurity
    signedPeStream.Seek(peFile.ImageDirectoryEntrySecurityOffset.toLong(), SeekOrigin.Begin)
    writer.Write(attributeCertificateTableOffset.toInt())
    writer.Write(encodedCmsSignedData.count())
    return signedPeStream
  }

  private fun createCmsSignedData(peFile: PeFile): ASN1Encodable {
    val digestInfo =
      DigestInfo(AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), peFile.ComputeHash("sha1"))
    val data = SpcAttributeOptional(ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.15"), SpcPeImageData())
    return SpcIndirectDataContent(data, digestInfo)
  }

  companion object {
    private fun getRootStoreStream(cert: X509CertificateHolder): InputStream {
      val cmsGen = CMSSignedDataGenerator()
      cmsGen.addCertificate(cert)
      val cmsSignedData = cmsGen.generate(CMSProcessableByteArray(ByteArray(0)), false)
      val data = cmsSignedData.encoded
      return ByteArrayInputStream(data)
    }

    private const val pe_01_not_signed = "ServiceModelRegUI_no_sign.dll"


    @JvmStatic
    fun FakePkiTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_not_signed)
      )
    }
  }
}