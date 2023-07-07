package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus
import com.jetbrains.signatureverifier.dmg.DmgFile
import com.jetbrains.util.TestUtil.getTestByteChannel
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class DmgSignatureVerifierTests {
  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(resourceName: String, expectedResult: VerifySignatureStatus) {
    val verificationParams = SignatureVerificationParams(null, null, false, false)
    val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)

    getTestByteChannel("dmg", resourceName).use {
      val dmgFile = DmgFile(it)
      val signatureData = dmgFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val result = runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

      Assertions.assertEquals(expectedResult, result.Status)
    }
  }

  @ParameterizedTest
  @MethodSource("ComputeHashTestProvider")
  fun ComputeHashTest(signedResource: String, unsignedResource: String, sameFile: Boolean) {
    getTestByteChannel("dmg", signedResource).use { signedStream ->
      val signedFile = DmgFile(signedStream)
      getTestByteChannel("dmg", unsignedResource).use { unsignedStream ->
        val unsignedFile = DmgFile(unsignedStream)
        listOf("SHA1", "SHA256").forEach { algorithm ->
          Assertions.assertEquals(
            sameFile,
            signedFile.ComputeHash(algorithm).contentEquals(unsignedFile.ComputeHash(algorithm))
          )
        }
      }
    }
  }

  companion object {
    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("steam.dmg", VerifySignatureStatus.Valid),
        Arguments.of("json-viewer.dmg", VerifySignatureStatus.Valid),
      )
    }

    @JvmStatic
    fun ComputeHashTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("steam.dmg", "steam_not_signed.dmg", true),
        Arguments.of("steam.dmg", "json-viewer.dmg", false),
      )
    }
  }
}