package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.BcExt.ConvertToHexString
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus
import com.jetbrains.util.TestUtil
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class MsiSignatureVerifierTests {
  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  fun VerifySignTest(resourceName: String, expectedResult: VerifySignatureStatus) {
    val result = TestUtil.getTestByteChannel("msi", resourceName).use {
      val verificationParams = SignatureVerificationParams(null, null, false, false)
      val msiFile = MsiFile(it)
      val signatureData = msiFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedMessageVerifier = SignedMessageVerifier(ConsoleLogger.Instance)
      runBlocking { signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams) }
    }
    Assertions.assertEquals(expectedResult, result.Status)
  }

  @ParameterizedTest
  @MethodSource("ComputeHashTestProvider")
  fun ComputeHashTest(resourceName: String, alg: String, expectedResult: String) {
    val result = TestUtil.getTestByteChannel("msi", resourceName).use {
      val msiFile = MsiFile(it)
      msiFile.ComputeHash(alg, skipMsiDigitalSignatureExEntry = true)
    }
    Assertions.assertEquals(expectedResult, result.ConvertToHexString().uppercase())
  }

  companion object {
    private const val msi_01_signed = "2dac4b.msi";
    private const val msi_02_signed = "firefox.msi";
    private const val msi_03_signed = "sumatra.msi";
    private const val msi_01_not_signed = "2dac4b_not_signed.msi";
    private const val msi_01_broken_hash = "2dac4b_broken_hash.msi";
    private const val msi_01_broken_sign = "2dac4b_broken_sign.msi";
    private const val msi_01_broken_timestamp = "2dac4b_broken_timestamp.msi";

    private const val msi_01_sha1 = "CBBE5C1017C8A65FFEB9219F465C949563A0E256";


    @JvmStatic
    fun VerifySignTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(msi_01_signed, VerifySignatureStatus.Valid),
        Arguments.of(msi_02_signed, VerifySignatureStatus.Valid),
        Arguments.of(msi_03_signed, VerifySignatureStatus.Valid),
        Arguments.of(msi_01_broken_hash, VerifySignatureStatus.InvalidSignature),
        Arguments.of(msi_01_broken_sign, VerifySignatureStatus.InvalidSignature),
        Arguments.of(msi_01_broken_timestamp, VerifySignatureStatus.InvalidSignature)
      )
    }

    @JvmStatic
    fun ComputeHashTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(msi_01_signed, "SHA1", msi_01_sha1),
        Arguments.of(msi_01_not_signed, "SHA1", msi_01_sha1)
      )
    }
  }
}