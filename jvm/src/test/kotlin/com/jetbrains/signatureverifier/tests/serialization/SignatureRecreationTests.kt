package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.serialization.Asn1PrimitiveSerializer
import com.jetbrains.signatureverifier.serialization.compareBytes
import com.jetbrains.signatureverifier.serialization.toContentInfo
import com.jetbrains.util.TestUtil
import com.jetbrains.util.TestUtil.getTestByteChannel
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.cms.SignedData
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class SignatureRecreationTests {

  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun PE_Test(signedPeResourceName: String) {
    getTestByteChannel("pe", signedPeResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)

      RecreateSignatureTest(signedMessage, peFile.GetSignatureData().CmsData!!)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMachoProvider")
  fun Macho_Test(signedResourceName: String) {
    val machoFiles =
      Files.newByteChannel(
        TestUtil.getTestDataFile(
          "mach-o",
          signedResourceName
        ), StandardOpenOption.READ
      ).use {
        MachoArch(it).Extract()
      }

    for (machoFile in machoFiles) {
      val signatureData = machoFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      RecreateSignatureTest(signedMessage, machoFile.GetSignatureData().CmsData!!, isMacho = true)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMsiProvider")
  fun Msi_Test(signedResourceName: String) {
    val result = TestUtil.getTestByteChannel("msi", signedResourceName).use {
      val msiFile = MsiFile(it)
      val signatureData = msiFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      RecreateSignatureTest(signedMessage, msiFile.GetSignatureData().CmsData!!)
    }
  }

  /**
   * Tests, that we can recreate original signature
   */
  fun RecreateSignatureTest(
    signedMessage: SignedMessage,
    originalSignature: ByteArray,
    isMacho: Boolean = false
  ) {
    val signedData = signedMessage.SignedData
    val innerSignedData = signedData.signedData

    val contentInfo = signedData.contentInfo
    val initialSignedDataInfo = signedData.signedData.toASN1Primitive()

    val json = Json.encodeToString(Asn1PrimitiveSerializer, initialSignedDataInfo)
    val deserializedSignedDataInfo = Json.decodeFromString(Asn1PrimitiveSerializer, json)

    val signedDataInfo = SignedData.getInstance(deserializedSignedDataInfo)

    if (isMacho) {
      Assertions.assertEquals(
        true,
        compareBytes(
          innerSignedData.getEncoded("DER"),
          signedDataInfo.getEncoded("DER"),
          verbose = true
        )
      )

      val recreatedInfo = SignedData.getInstance(signedDataInfo).toContentInfo()

      Assertions.assertEquals(
        true,
        compareBytes(
          contentInfo.getEncoded("BER"),
          recreatedInfo.getEncoded("BER"),
          verbose = true
        )
      )

      val encoded = recreatedInfo.getEncoded("BER")

      Assertions.assertEquals(
        true,
        compareBytes(
          originalSignature,
          encoded,
          verbose = false
        )
      )
    } else {

      Assertions.assertEquals(
        true,
        compareBytes(
          innerSignedData.getEncoded("DER"),
          signedDataInfo.getEncoded("DER"),
          verbose = true
        )
      )

      val recreatedInfo = SignedData.getInstance(signedDataInfo).toContentInfo()

      Assertions.assertEquals(
        true,
        compareBytes(
          contentInfo.getEncoded("DER"),
          recreatedInfo.getEncoded("DER"),
          verbose = true
        )
      )

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
    fun SignedMsiProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("2dac4b.msi"),
        Arguments.of("firefox.msi"),
        Arguments.of("sumatra.msi"),
      )
    }

    @JvmStatic
    fun SignedMachoProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("nosigned_resigned"),
        Arguments.of("env-wrapper.x64"),
        Arguments.of("libMonoSupportW.x64.dylib"),
        Arguments.of("cat"),
        Arguments.of("JetBrains.Profiler.PdbServer"),
        Arguments.of("fat.dylib_signed"),
        Arguments.of("libhostfxr.dylib")
      )
    }

    @JvmStatic
    fun SignedPEProvider(): Stream<Arguments> {
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
          pe_08_signed
        ),
        Arguments.of(
          "JetBrains.ReSharper.TestResources.dll"
        ),
        Arguments.of(
          "System.Security.Principal.Windows.dll"
        ),
      )
    }
  }
}