package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus
import com.jetbrains.signatureverifier.dmg.DmgFile
import com.jetbrains.signatureverifier.serialization.getTestByteChannel
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

  companion object {
    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("steam.dmg", VerifySignatureStatus.Valid),
        Arguments.of("json-viewer.dmg", VerifySignatureStatus.Valid),
      )
    }
  }
}