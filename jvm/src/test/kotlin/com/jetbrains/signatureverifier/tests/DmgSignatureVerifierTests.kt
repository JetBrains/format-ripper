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
  fun ComputeHashTest(resource: String, algorithm: String, expectedSignature: String) {
    getTestByteChannel("dmg", resource).use { signedStream ->
      val signedFile = DmgFile(signedStream)
      Assertions.assertEquals(
        expectedSignature,
        signedFile.ComputeHash(algorithm).toHexString()
      )
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
        Arguments.of("steam.dmg", "sha1", "02A79BE766434D8D5846840074B732F07B9991B6"),
        Arguments.of("steam_not_signed.dmg", "sha1", "02A79BE766434D8D5846840074B732F07B9991B6"),
        Arguments.of("steam.dmg", "sha256", "5BCD5694E10BB1EEDE33414D5A53A243687E524CA48420FCA03F3F0911732F77"),
        Arguments.of(
          "steam_not_signed.dmg",
          "sha256",
          "5BCD5694E10BB1EEDE33414D5A53A243687E524CA48420FCA03F3F0911732F77"
        ),
        Arguments.of("json-viewer.dmg", "sha1", "A4DD9A946EC0973C826FFE78E24E5CF2BCADA774"),
        Arguments.of("json-viewer.dmg", "sha256", "068878BE00AA22A4056A7976C414DB60D1D874804FDAC1549AB5F883D2C6968B"),
      )
    }

    fun ByteArray.toHexString(): String {
      val hexChars = "0123456789ABCDEF"
      val result = StringBuilder(size * 2)
      for (byte in this) {
        val value = byte.toInt() and 0xFF
        result.append(hexChars[value ushr 4])
        result.append(hexChars[value and 0x0F])
      }
      return result.toString()
    }
  }
}