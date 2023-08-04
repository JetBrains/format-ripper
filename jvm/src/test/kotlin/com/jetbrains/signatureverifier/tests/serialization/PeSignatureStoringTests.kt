package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.serialization.fileInfos.PEFileInfo
import com.jetbrains.signatureverifier.serialization.fileInfos.PeFileMetaInfo
import com.jetbrains.signatureverifier.serialization.compareBytes
import com.jetbrains.util.TestUtil
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.util.*
import java.util.stream.Stream
import kotlin.io.path.copyTo
import kotlin.io.path.deleteExisting

class PeSignatureStoringTests {

  @ParameterizedTest
  @MethodSource("InsertSignatureTestProvider")
  fun InsertSignatureTest(signedPeResourceName: String, unsignedPeResourceName: String) {
    if (signedPeResourceName != unsignedPeResourceName) {
      Assertions.assertNotEquals(
        Files.mismatch(
          TestUtil.getTestDataFile("pe", signedPeResourceName),
          TestUtil.getTestDataFile("pe", unsignedPeResourceName)
        ),
        -1
      )
    }

    val peFileMetaInfo: PeFileMetaInfo
    val signature: ByteArray
    val peFileInfo: PEFileInfo

    TestUtil.getTestByteChannel("pe", signedPeResourceName, write = true).use {
      val peFile = PeFile(it)
      peFileInfo = PEFileInfo(peFile)

      Assertions.assertEquals(
        true,
        compareBytes(peFileInfo.signedDataInfo.toSignature(), peFile.GetSignatureData().CmsData!!, verbose = false)
      )
    }

    val path = TestUtil.getTestDataFile("pe", unsignedPeResourceName)
    val tmpName = "tmp" + Random().nextInt().toString()
    val tmpFile = path.parent.resolve(tmpName)
    path.copyTo(tmpFile)


    TestUtil.getTestByteChannel("pe", tmpName, write = true).use {
      peFileInfo.modifyFile(it)
    }

    Assertions.assertEquals(
      Files.mismatch(
        TestUtil.getTestDataFile("pe", signedPeResourceName),
        TestUtil.getTestDataFile("pe", tmpName)
      ),
      -1
    )
    tmpFile.deleteExisting()
  }

  companion object {
    private const val pe_01_signed = "ServiceModelRegUI.dll"
    private const val pe_01_not_signed = "ServiceModelRegUI_no_sign.dll"

    private const val pe_02_signed = "self_signed_test.exe"
    private const val pe_02_not_signed = "self_signed_test_no_sign.exe"

    private const val pe_03_signed = "shell32.dll"
    private const val pe_03_not_signed = "shell32_no_sign.dll"

    private const val pe_04_signed = "IntelAudioService.exe"
    private const val pe_04_not_signed = "IntelAudioService_no_sign.exe"

    private const val pe_05_signed = "libcrypto-1_1-x64.dll"
    private const val pe_05_not_signed = "libcrypto-1_1-x64_no_sign.dll"

    private const val pe_06_signed = "libssl-1_1-x64.dll"
    private const val pe_06_not_signed = "libssl-1_1-x64_no_sign.dll"

    private const val pe_07_signed = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe"
    private const val pe_07_not_signed =
      "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web_no_sign.exe"

    private const val pe_08_signed = "dotnet.exe"
    private const val pe_08_not_signed = "dotnet_no_sign.exe"


    @JvmStatic
    fun InsertSignatureTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of(
          pe_01_signed, pe_01_not_signed
        ),
        Arguments.of(
          pe_02_signed, pe_02_not_signed
        ),
        Arguments.of(
          pe_03_signed, pe_03_not_signed
        ),
        Arguments.of(
          pe_04_signed, pe_04_not_signed
        ),
        Arguments.of(
          pe_05_signed, pe_05_not_signed
        ),
        Arguments.of(
          pe_06_signed, pe_06_not_signed
        ),
        Arguments.of(
          pe_07_signed, pe_07_not_signed
        ),
        Arguments.of(
          pe_08_signed, pe_08_not_signed
        ),
        Arguments.of(
          "JetBrains.ReSharper.TestResources.dll", "JetBrains.ReSharper.TestResources.dll"
        ),Arguments.of(
          "System.Security.Principal.Windows.dll", "System.Security.Principal.Windows.dll"
        ),
      )
    }
  }

}