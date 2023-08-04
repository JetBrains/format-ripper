package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.serialization.dataholders.CertificateInfo
import com.jetbrains.signatureverifier.serialization.compareBytes
import com.jetbrains.signatureverifier.serialization.fileInfos.getTestByteChannel
import com.jetbrains.signatureverifier.serialization.dataholders.recreateCertificatesFromStore
import com.jetbrains.util.TestUtil
import org.bouncycastle.util.CollectionStore
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class CertificateSerializationTests {

  /**
   * Tests, that we can recreate `certificates` field of `SignedData` from serialized data
   */
  @ParameterizedTest
  @MethodSource("SignedPEProvider")
  fun PE_RecreateCertificatesTest(signedResourceName: String) {
    getTestByteChannel("pe", signedResourceName).use {
      val peFile = PeFile(it)
      val signatureData = peFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      RecreateCertificatesTest(signedMessage)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMachoProvider")
  fun Macho_RecreateCertificatesTest(signedResourceName: String) {
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
      RecreateCertificatesTest(signedMessage)
    }
  }

  @ParameterizedTest
  @MethodSource("SignedMsiProvider")
  fun Msi_RecreateCertificatesTest(signedResourceName: String) {
    val result = TestUtil.getTestByteChannel("msi", signedResourceName).use {
      val verificationParams = SignatureVerificationParams(null, null, false, false)
      val msiFile = MsiFile(it)
      val signatureData = msiFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      RecreateCertificatesTest(signedMessage)
    }
  }

  fun RecreateCertificatesTest(signedMessage: SignedMessage) {
    val signedData = signedMessage.SignedData
    val innerSignedData = signedData.signedData

    val beautifiedCertificates = signedData.certificates.getMatches(null).toList()

    val recreatedList = beautifiedCertificates.map { certificateHolder ->

      val certificateInfo = CertificateInfo.getInstance(certificateHolder)

      val recreatedCertificateHolder = certificateInfo.toX509CertificateHolder()

      Assertions.assertEquals(
        true,
        compareBytes(
          recreatedCertificateHolder.encoded,
          certificateHolder.encoded,
          verbose = false
        )
      )
      recreatedCertificateHolder
    }

    val recreatedStore = CollectionStore(recreatedList)
    val recreatedCertificates = recreateCertificatesFromStore(recreatedStore)

    Assertions.assertEquals(
      true,
      compareBytes(
        recreatedCertificates.getEncoded("DER"),
        innerSignedData.certificates.getEncoded("DER"),
        verbose = false
      )
    )
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
          pe_08_signed, pe_08_not_signed
        ),
      )
    }
  }

}