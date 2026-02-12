package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.BcExt.ConvertToHexString
import com.jetbrains.signatureverifier.powershell.PowershellScriptFile
import com.jetbrains.util.TestUtil.getTestDataFile
import org.apache.commons.io.ByteOrderMark
import org.apache.commons.io.ByteOrderMark.UTF_BOM
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class PowerShellComputeHashTest {
  @ParameterizedTest
  @MethodSource("PowerShellComputeHashTestProvider")
  fun ComputeHashTest(resourceName: String, expectedResult: String) {
    Files.newByteChannel(getTestDataFile("powershell", resourceName), StandardOpenOption.READ).use {
      val file = PowershellScriptFile(it)

      // Hash is computed from content encoded as UTF-16LE
      val result = file.ComputeHash("SHA-256")
      Assertions.assertEquals(expectedResult, result.ConvertToHexString().uppercase())
    }
  }

  @ParameterizedTest
  @MethodSource("PowerShellContentAndBOM")
  fun CheckContentWithoutSignature(resourceName: String, eol: String, bom: ByteOrderMark?) {
    Files.newByteChannel(getTestDataFile("powershell", resourceName), StandardOpenOption.READ).use {
      val file = PowershellScriptFile(it)
      val content = file.GetContentWithoutSignature()
      if (bom != null) {
        Assertions.assertEquals(UTF_BOM.code, content[0].code)
        Assertions.assertEquals(CONTENT.replace("<EOL>", eol), content.drop(1))
      } else {
        Assertions.assertNotEquals(UTF_BOM.code, content[0].code)
        Assertions.assertEquals(CONTENT.replace("<EOL>", eol), content)
      }
    }
  }

  companion object {
    const val CONTENT = "Write-Host \"PSExecutionPolicyPreference is '$(\$env:PSExecutionPolicyPreference)'\"<EOL>" +
      "Write-Host \"Some Unicode characters just to check encoding: Юникод ꙮ\uD83C\uDCA1\uD83D\uDE0E\""
    @JvmStatic
    fun PowerShellComputeHashTestProvider(): Stream<Arguments> {
      val hashLF = "8F47E600DC6399B506C1F8F1E57F98026FDF9EA119FF19BDE92EDD670EE8E46D"
      val hashCRLF = "26281693B5A646B765591BE3A47D3DDBD99B76B91BAA1760ED6A069C9C877C97"
      val hashLF_no_BOM = "1D5B22A7CC0752D27D6A460BD38AC5B255E48B679D0149510CD63003DCA29B2C"
      val hashCRLF_no_BOM = "8A441A48D8922E06288C9D1C495DA2C399B00CDA5350163287F1DB6A9265B0D7"

      return Stream.of(
        Arguments.of("script-utf-8-no-bom-crlf.ps1", hashCRLF_no_BOM),
        Arguments.of("script-utf-8-no-bom-lf.ps1", hashLF_no_BOM),
        Arguments.of("script-utf-8-bom-crlf.ps1", hashCRLF),
        Arguments.of("script-utf-8-bom-lf.ps1", hashLF),
        Arguments.of("script-utf-16be-crlf.ps1", hashCRLF),
        Arguments.of("script-utf-16be-lf.ps1", hashLF),
        Arguments.of("script-utf-16le-crlf.ps1", hashCRLF),
        Arguments.of("script-utf-16le-lf.ps1", hashLF),
        Arguments.of("signed-script-utf-8-no-bom-crlf.ps1", hashCRLF_no_BOM),
        Arguments.of("signed-script-utf-8-no-bom-lf.ps1", hashLF_no_BOM),
        Arguments.of("signed-script-utf-8-bom-crlf.ps1", hashCRLF),
        Arguments.of("signed-script-utf-8-bom-lf.ps1", hashLF),
        Arguments.of("signed-script-utf-16be-crlf.ps1", hashCRLF),
        Arguments.of("signed-script-utf-16be-lf.ps1", hashLF),
        Arguments.of("signed-script-utf-16le-crlf.ps1", hashCRLF),
        Arguments.of("signed-script-utf-16le-lf.ps1", hashLF),
        //Arguments.of("corrupted-script-utf-8-no-bom.ps1", mainHash),
      )
    }

    @JvmStatic
    fun PowerShellContentAndBOM(): Stream<Arguments> {
      val CRLF = "\u000D\u000A"
      val LF = "\u000A"
      return Stream.of(
        Arguments.of("script-utf-8-no-bom-crlf.ps1", CRLF, null),
        Arguments.of("script-utf-8-no-bom-lf.ps1", LF, null),
        Arguments.of("script-utf-8-bom-crlf.ps1", CRLF, ByteOrderMark.UTF_8),
        Arguments.of("script-utf-8-bom-lf.ps1", LF, ByteOrderMark.UTF_8),
        Arguments.of("script-utf-16be-crlf.ps1", CRLF, ByteOrderMark.UTF_16BE),
        Arguments.of("script-utf-16be-lf.ps1", LF, ByteOrderMark.UTF_16BE),
        Arguments.of("script-utf-16le-crlf.ps1", CRLF, ByteOrderMark.UTF_16LE),
        Arguments.of("script-utf-16le-lf.ps1", LF, ByteOrderMark.UTF_16LE),
        Arguments.of("signed-script-utf-8-no-bom-crlf.ps1", CRLF, null),
        Arguments.of("signed-script-utf-8-no-bom-lf.ps1", LF, null),
        Arguments.of("signed-script-utf-8-bom-crlf.ps1", CRLF, ByteOrderMark.UTF_8),
        Arguments.of("signed-script-utf-8-bom-lf.ps1", LF, ByteOrderMark.UTF_8),
        Arguments.of("signed-script-utf-16be-crlf.ps1", CRLF, ByteOrderMark.UTF_16BE),
        Arguments.of("signed-script-utf-16be-lf.ps1", LF, ByteOrderMark.UTF_16BE),
        Arguments.of("signed-script-utf-16le-crlf.ps1", CRLF, ByteOrderMark.UTF_16LE),
        Arguments.of("signed-script-utf-16le-lf.ps1", LF, ByteOrderMark.UTF_16LE),
        //Arguments.of("corrupted-script-utf-8-no-bom.ps1", null),
      )
    }
  }
}