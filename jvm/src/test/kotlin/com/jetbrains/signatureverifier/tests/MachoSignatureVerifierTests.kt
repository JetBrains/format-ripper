package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus
import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.util.TestUtil.getTestDataFile
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class MachoSignatureVerifierTests {
  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(machoResourceName: String, expectedResult: VerifySignatureStatus) {
    val machoFiles =
      Files.newByteChannel(getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ).use {
        MachoArch(it).Extract()
      }

    val verificationParams = SignatureVerificationParams(null, null, false, false)
    val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)

    for (machoFile in machoFiles) {
      val signatureData = machoFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val result = runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }

      Assertions.assertEquals(expectedResult, result.Status)
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignInvalidSignatureFormatTestProvider")
  fun VerifySignInvalidSignatureFormat(machoResourceName: String) {
    val machoFiles =
      Files.newByteChannel(getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ).use {
        MachoArch(it).Extract()
      }

    for (machoFile in machoFiles) {
      val signatureData = machoFile.GetSignatureData()
      val thrown = assertThrows(Exception::class.java) { SignedMessage.CreateInstance(signatureData) }
      assertTrue(thrown.message!!.contains("Invalid signature format"))
    }
  }


  companion object {
    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("nosigned_resigned", VerifySignatureStatus.Valid),
        Arguments.of("env-wrapper.x64", VerifySignatureStatus.Valid),
        Arguments.of("libMonoSupportW.x64.dylib", VerifySignatureStatus.Valid),
        Arguments.of("cat", VerifySignatureStatus.Valid),
        Arguments.of("JetBrains.Profiler.PdbServer", VerifySignatureStatus.Valid),
        Arguments.of("fat.dylib_signed", VerifySignatureStatus.Valid),
        Arguments.of("libhostfxr.dylib", VerifySignatureStatus.Valid)
      )
    }

    @JvmStatic
    fun VerifySignInvalidSignatureFormatTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("libSystem.Net.Security.Native.dylib")
      )
    }
  }
}