package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.cms.SignedData
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import java.util.stream.Stream

class SignatureRecreationTests {

  /**
   * Tests, that we can recreate original signature
   */
  @ParameterizedTest
  @MethodSource("RecreateSignatureTestProvider")
  fun RecreateSignatureTest(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      val signedData = signedMessage.SignedData
      val innerSignedData = signedData.signedData

      val contentInfo = signedData.contentInfo
      val signedDataInfo = SignedDataInfo(signedData)
      val json = Json.encodeToString(signedDataInfo)
      val deserializedSignedDataInfo = Json.decodeFromString<SignedDataInfo>(json)

      val copy = SignedData.getInstance(deserializedSignedDataInfo.toPrimitive())

      Assertions.assertEquals(
        true,
        compareBytes(
          innerSignedData.getEncoded("DER"),
          copy.getEncoded("DER"),
          verbose = true
        )
      )

      val recreatedInfo = recreateContentInfoFromSignedData(copy)

      Assertions.assertEquals(
        true,
        compareBytes(
          contentInfo.getEncoded("DER"),
          recreatedInfo.getEncoded("DER"),
          verbose = false
        )
      )

      val originalSignature = peFile.GetSignatureData().CmsData!!

      val encoded = recreatedInfo.getEncoded("DER")

      Assertions.assertEquals(
        true,
        compareBytes(
          originalSignature,
          encoded,
          verbose = false
        )
      )
    }
  }

  companion object {
    private const val pe_01_signed = "ServiceModelRegUI.dll"

    private const val pe_02_signed = "self_signed_test.exe"

    private const val pe_03_signed = "shell32.dll"

    private const val pe_04_signed = "IntelAudioService.exe"

    private const val pe_05_signed = "libcrypto-1_1-x64.dll"

    private const val pe_06_signed = "libssl-1_1-x64.dll"

    private const val pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe"

    private const val pe_08_signed = "dotnet.exe"
    private const val pe_08_not_signed = "dotnet_no_sign.exe"


    @JvmStatic
    fun RecreateSignatureTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(
          pe_01_signed
        ),
        Arguments.of(
          pe_02_signed
        ),
        Arguments.of(
          pe_03_signed
        ),
        Arguments.of(
          pe_04_signed
        ),
        Arguments.of(
          pe_05_signed
        ),
        Arguments.of(
          pe_06_signed
        ),
        Arguments.of(
          pe_07_signed
        ),
        Arguments.of(
          pe_08_signed, pe_08_not_signed
        ),
      )
    }
  }

}