package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.*
import com.jetbrains.signatureverifier.crypt.BcExt.ConvertToHexString
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToLocalDateTime
import com.jetbrains.util.TestUtil.getTestByteChannel
import com.jetbrains.util.TestUtil.getTestDataInputStream
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
    private const val pe_07_sha384 = "0BF275099F6C5A3F86DC2C2F7396D0BA750345ED2947F79681919AA8B8CD030454E09AB5AC8D95EC9D8695A95B1DCB0E"

    private const val jb_codesign_roots = "jb_codesign_roots.p7b"
    private const val jb_timestamp_roots = "jb_timestamp_roots.p7b"

    private const val pe_08_signed = "dotnet.exe"
    private const val pe_09_broken_timestamp = "dotnet_broken_timestamp.exe"

    private const val pe_10_signed = "JetBrains.ReSharper.TestResources.dll"
    private const val pe_10_sha384 = "8216D6CA73079467F63E8F5822D425C48D5C415171E72F480AFFF4A1AD4BEC7750457BE0330EA28850C2CD44E72810C1"

    private const val pe_11_signed = "System.Security.Principal.Windows.dll"
    private const val pe_11_sha512 = "A4F2B45274C4CF912489BE463EB38FD817734B14232B9A9EC8B7B4C860E3200BC80C33F44F3DD7108525BF2F15F064B3B776371D266921133FA59D2990BDA22F"

    private const val pe_12_signed = "winrsmgr.arm.dll"
    private const val pe_12_sha384 = "1768CC1A046874A40E2C2A0BB9C6F353F2944B8C1DA70CFD9BDD9ECA92217A2DFFD290775E31CF5FF5391C3D2770BEFE"

    private const val pe_13_signed = "winrsmgr.arm64.dll"
    private const val pe_13_sha384 = "9DAB8C315D97965AB3C64BE91F88F6DE3AF06ACB1E122F897AD5515A9731A345F96AB6F5738A201CCB14850068BBD9F9"

    private const val pe_14_signed = "winrsmgr.x64.dll"
    private const val pe_14_sha384 = "B02129BEC77CE3FA473C93C5021313BF8790221067B3D764B54B5DF51DAD58F70E66EF8C74CEDE94A1E6980D83800469"

    private const val pe_15_signed = "winrsmgr.x86.dll"
    private const val pe_15_sha384 = "736F11CB4B4B51C001155DD045A0C91E3E3104821D2D5B269514358351915203E1DAF313D616B573CE063C1E1DECDDC9"

    private const val pe_16_signed = "wscadminui.arm.exe"
    private const val pe_16_sha256 = "1922FF5BB8645F542BEEBD369210FB9E61A06EF53DE75D4B3BC5B42BFA9903B7"

    private const val pe_17_signed = "wscadminui.arm64.exe"
    private const val pe_17_sha256 = "7D2B0F75106C52CD14C478B01A931B629A6937380DB83AC08F9CBDAEBC531EF6"

    private const val pe_18_signed = "wscadminui.x64.exe"
    private const val pe_18_sha256 = "1EDDACFA399B9287C5002D1E94AC8D44CC2F27FAEC29C30CDE84ED2B9E478B0A"

    private const val pe_19_signed = "wscadminui.x86.exe"
    private const val pe_19_sha256 = "8989E8F8C9E81E18BBDA215F78C3DFBBFCAD8341B265AB3AE89D749E6D9349A8"
      @JvmStatic
    fun ComputeHashTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_not_signed, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_signed, "SHA-256", pe_01_sha256),
        Arguments.of(pe_01_not_signed, "SHA-256", pe_01_sha256),
        Arguments.of(pe_01_trimmed_sign, "SHA-1", pe_01_sha1),
        Arguments.of(pe_01_trimmed_sign, "SHA-256", pe_01_sha256),
        Arguments.of(pe_01_empty_sign, "SHA-1", pe_01_sha1),
        Arguments.of(pe_02_empty_sign, "SHA-1", pe_02_sha1),
        Arguments.of(pe_03_signed, "SHA-256", pe_03_sha256),
        Arguments.of(pe_04_signed, "SHA-256", pe_04_sha256),
        Arguments.of(pe_07_signed, "SHA-384", pe_07_sha384),
        Arguments.of(pe_10_signed, "SHA-384", pe_10_sha384),
        Arguments.of(pe_11_signed, "SHA-512", pe_11_sha512),
        Arguments.of(pe_12_signed, "SHA-384", pe_12_sha384),
        Arguments.of(pe_13_signed, "SHA-384", pe_13_sha384),
        Arguments.of(pe_14_signed, "SHA-384", pe_14_sha384),
        Arguments.of(pe_15_signed, "SHA-384", pe_15_sha384),
        Arguments.of(pe_16_signed, "SHA-256", pe_16_sha256),
        Arguments.of(pe_17_signed, "SHA-256", pe_17_sha256),
        Arguments.of(pe_18_signed, "SHA-256", pe_18_sha256),
        Arguments.of(pe_19_signed, "SHA-256", pe_19_sha256),

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
        Arguments.of(pe_09_broken_timestamp, VerifySignatureStatus.InvalidTimestamp),
        Arguments.of(pe_10_signed, VerifySignatureStatus.Valid)
      )
    }

    @JvmStatic
    fun VerifySignWithChainTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(pe_01_signed, VerifySignatureStatus.Valid, ms_codesign_roots, ms_timestamp_root),
        Arguments.of(pe_07_signed, VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots),
        Arguments.of(pe_10_signed, VerifySignatureStatus.Valid, jb_codesign_roots, jb_timestamp_roots),
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
