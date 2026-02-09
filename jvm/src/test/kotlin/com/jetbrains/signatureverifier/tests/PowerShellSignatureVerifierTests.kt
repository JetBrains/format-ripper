package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.*
import com.jetbrains.signatureverifier.powershell.PowerShellScriptFile
import com.jetbrains.util.TestUtil.getTestByteChannel
import com.jetbrains.util.TestUtil.getTestDataInputStream
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.fail
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class PowerShellSignatureVerifierTests {
  private val simpleVerificationParams =
    SignatureVerificationParams(null, null, buildChain = false, withRevocationCheck = false)

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(resourceName: String, expectedResult: VerifySignatureStatus) {
    val result = getTestByteChannel("powershell", resourceName).use {
      val psFile = PowerShellScriptFile(it)
      val signatureData = psFile.GetSignatureData()
      if (signatureData.IsEmpty) {
        return@use VerifySignatureResult(VerifySignatureStatus.InvalidSignature, "Cannot extract signature from file")
      }

      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val result = psFile.VerifyContentHash(signedMessage.SignedData, psFile)
      if (result.NotValid) {
        return@use result
      }

      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, simpleVerificationParams) }
    }

    if (expectedResult != result.Status) {
      fail("Expected status: $expectedResult, but got: ${result.Status}, message: ${result.Message}")
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  fun VerifySignWithChainTest(
    resourceName: String,
    expectedResult: VerifySignatureStatus,
  ) {
    val result = getTestDataInputStream("powershell", resourceName).use {
      val file = PowerShellScriptFile(it)
      val signatureData = file.GetSignatureData()
      if (signatureData.IsEmpty) {
        return@use VerifySignatureResult(VerifySignatureStatus.InvalidSignature, "Cannot extract signature from file")
      }

      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, chainVerificationParams) }
    }

    if (expectedResult != result.Status) {
      fail("Expected status: $expectedResult, but got: ${result.Status}, message: ${result.Message}")
    }
  }

  private val chainVerificationParams by lazy {
    getTestDataInputStream("powershell", DIGICERT_ROOT_G4).use { codesignroots ->
      getTestDataInputStream("powershell", DIGICERT_ROOT_G4).use { timestamproots ->
        SignatureVerificationParams(
          codesignroots, timestamproots, buildChain = true, withRevocationCheck = false
        ).apply {
          this.RootCertificates // fully read streams, so they could be closed
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
