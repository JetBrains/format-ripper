package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.*
import com.jetbrains.signatureverifier.crypt.BcExt.ConvertToHexString
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToLocalDateTime
import com.jetbrains.signatureverifier.tests.TestUtil.getTestByteChannel
import com.jetbrains.signatureverifier.tests.TestUtil.getTestDataInputStream
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.time.LocalDateTime
import java.util.*
import java.util.stream.Stream

class PeSignatureVerifierTests {
  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(peResourceName: String, expectedResult: VerifySignatureStatus) {
    val result = getTestByteChannel("pe", peResourceName).use {
      val verificationParams = SignatureVerificationParams(null, null, false, false)
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }
    }
    assertEquals(expectedResult, result.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  fun VerifySignWithChainTest(
    peResourceName: String,
    expectedResult: VerifySignatureStatus,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String
  ) {
    val result = getTestByteChannel("pe", peResourceName).use { peFileStream ->
      getTestDataInputStream("pe", codesignRootCertStoreResourceName).use { codesignroots ->
        getTestDataInputStream("pe", timestampRootCertStoreResourceName).use { timestamproots ->
          val verificationParams = SignatureVerificationParams(
            codesignroots, timestamproots, buildChain = true, withRevocationCheck = false
          )

          val peFile = PeFile(peFileStream)
          val signatureData = peFile.GetSignatureData()
          val signedMessage = SignedMessage.CreateInstance(signatureData)
          val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
          runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }
        }
      }
    }

    assertEquals(expectedResult, result.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInPastProvider")
  fun VerifySignWithChainTestInPast(
    peResourceName: String,
    expectedResult: VerifySignatureStatus,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String
  ) {
    val actual = runBlocking {
      VerifySignWithChainTestInTime(
        peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        Date(Long.MIN_VALUE).ConvertToLocalDateTime()
      )
    }
    assertEquals(expectedResult, actual.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInPresentProvider")
  fun VerifySignWithChainTestInPresent(
    peResourceName: String,
    expectedResult: VerifySignatureStatus,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String
  ) {
    val actual = runBlocking {
      VerifySignWithChainTestInTime(
        peResourceName, codesignRootCertStoreResourceName, timestampRootCertStoreResourceName, LocalDateTime.now()
      )
    }
    assertEquals(expectedResult, actual.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInFutureProvider")
  fun VerifySignWithChainTestInFuture(
    peResourceName: String,
    expectedResult: VerifySignatureStatus,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String
  ) {
    val actual = runBlocking {
      VerifySignWithChainTestInTime(
        peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        Date(Long.MAX_VALUE).ConvertToLocalDateTime()
      )
    }
    assertEquals(expectedResult, actual.Status)
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestAboutSignTimeProvider")
  fun VerifySignWithChainTestAboutSignTime(
    peResourceName: String,
    expectedResult: VerifySignatureStatus,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String
  ) {
    val actual = runBlocking {
      VerifySignWithChainTestInTime(
        peResourceName,
        codesignRootCertStoreResourceName,
        timestampRootCertStoreResourceName,
        LocalDateTime.of(2019, 11, 24, 0, 0)
      )
    }
    assertEquals(expectedResult, actual.Status)
  }

  private fun VerifySignWithChainTestInTime(
    peResourceName: String,
    codesignRootCertStoreResourceName: String,
    timestampRootCertStoreResourceName: String,
    time: LocalDateTime
  ): VerifySignatureResult {
    return getTestByteChannel("pe", peResourceName).use { peFileStream ->
      getTestDataInputStream("pe", codesignRootCertStoreResourceName).use { codesignroots ->
        getTestDataInputStream("pe", timestampRootCertStoreResourceName).use { timestamproots ->
          val verificationParams = SignatureVerificationParams(
            codesignroots,
            timestamproots,
            buildChain = true,
            withRevocationCheck = false,
            ocspResponseTimeout = null,
            SignatureValidationTimeMode.SignValidationTime,
            signatureValidationTime = time
          )

          val peFile = PeFile(peFileStream)
          val signatureData = peFile.GetSignatureData()
          val signedMessage = SignedMessage.CreateInstance(signatureData)
          val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
          runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("ComputeHashTestProvider")
  fun ComputeHashTest(peResourceName: String, alg: String, expectedResult: String) {
    val result = getTestByteChannel("pe", peResourceName).use {
      val peFile = PeFile(it)
      peFile.ComputeHash(alg)
    }
    assertEquals(expectedResult, result.ConvertToHexString().uppercase())
  }

  @ParameterizedTest
  @MethodSource("VerifyIsDotNetProvider")
  fun IsDotNetTest(peResourceName: String, expectedResult: Boolean) {
    val result = getTestByteChannel("pe", peResourceName).use {
      val peFile = PeFile(it)
      peFile.IsDotNet
    }
    assertEquals(expectedResult, result)
  }

  companion object {
    private const val pe_01_signed = "ServiceModelRegUI.dll"
    private const val pe_01_not_signed = "ServiceModelRegUI_no_sign.dll"
    private const val pe_01_trimmed_sign = "ServiceModelRegUI_trimmed_sign.dll"
    private const val pe_01_empty_sign = "ServiceModelRegUI_empty_sign.dll"
    private const val pe_01_broken_hash = "ServiceModelRegUI_broken_hash.dll"
    private const val pe_01_sha1 = "D64EC6AEC642441554E7CBA0E0513E35683C87AE"
    private const val pe_01_broken_sign = "ServiceModelRegUI_broken_sign.dll"
    private const val pe_01_broken_counter_sign = "ServiceModelRegUI_broken_counter_sign.dll"
    private const val pe_01_broken_nested_sign = "ServiceModelRegUI_broken_nested_sign.dll"
    private const val pe_01_broken_nested_sign_timestamp = "ServiceModelRegUI_broken_nested_sign_timestamp.dll"
    private const val pe_01_sha256 = "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A"
    private const val ms_codesign_roots = "ms_codesign_roots.p7b"
    private const val ms_timestamp_root = "ms_timestamp_root.p7b"

    private const val pe_02_empty_sign = "uninst.exe"
    private const val pe_02_sha1 = "58AA2C6CF6A446426F3596F1BC4AB4E1FAAC297A"

    private const val pe_03_signed = "shell32.dll"
    private const val pe_03_sha256 = "BB79CC7089BF061ED707FFB3FFA4ADE1DDAED0396878CC92D54A0E20A3C81619"

    private const val pe_04_signed = "IntelAudioService.exe"
    private const val pe_04_sha256 = "160F2FE667A9252AB5B2E01749CD40B024E749B10B49AD276345875BA073A57E"

    private const val pe_05_signed = "libcrypto-1_1-x64.dll"
    private const val pe_06_signed = "libssl-1_1-x64.dll"
    private const val pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe"
    private const val jb_codesign_roots = "jb_codesign_roots.p7b"
    private const val jb_timestamp_roots = "jb_timestamp_roots.p7b"

    private const val pe_08_signed = "dotnet.exe"
    private const val pe_09_broken_timestamp = "dotnet_broken_timestamp.exe"

    @JvmStatic
    fun ComputeHashTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_not_signed, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_signed, "SHA-256", pe_01_sha256),
        Arguments.of(pe_01_not_signed, "SHA-256", pe_01_sha256),
        Arguments.of(pe_01_trimmed_sign, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_empty_sign, "SHA-1", pe_01_sha1),
        Arguments.of(pe_02_empty_sign, "SHA-1", pe_02_sha1),
        Arguments.of(pe_03_signed, "SHA-256", pe_03_sha256),
        Arguments.of(pe_04_signed, "SHA-256", pe_04_sha256)
      )
    }

    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.Valid),
        Arguments.of(pe_01_broken_hash, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_01_broken_sign, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_01_broken_counter_sign, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_01_broken_nested_sign, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_01_broken_nested_sign_timestamp, VerifySignatureStatus.InvalidTimestamp),
        Arguments.of(pe_03_signed, VerifySignatureStatus.Valid),
        Arguments.of(pe_04_signed, VerifySignatureStatus.Valid),
        Arguments.of(pe_05_signed, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_06_signed, VerifySignatureStatus.InvalidSignature),
        Arguments.of(pe_07_signed, VerifySignatureStatus.Valid),
        Arguments.of(pe_09_broken_timestamp, VerifySignatureStatus.InvalidTimestamp)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root),
        Arguments.of(pe_07_signed, VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots),
        Arguments.of(pe_08_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestInPastProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestInPresentProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestInFutureProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.InvalidChain, ms_codesign_roots, ms_timestamp_root)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestAboutSignTimeProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root)
      )
    }

    @JvmStatic
    fun VerifyIsDotNetProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, false),
        Arguments.of(pe_04_signed, true)
      )
    }
  }
}
