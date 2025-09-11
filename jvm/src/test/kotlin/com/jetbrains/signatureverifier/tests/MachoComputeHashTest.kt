package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.crypt.BcExt.ConvertToHexString
import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.macho.MachoFile
import com.jetbrains.util.TestUtil.getTestDataFile
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class MachoComputeHashTest {
  @ParameterizedTest
  @MethodSource("MachoComputeHashTestProvider")
  fun ComputeHashTest(machoResourceName: String, alg: String, expectedResult: Collection<String>) {
    Files.newByteChannel(getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ).use {
      val machoFiles = MachoArch(it).Extract()

      for (index in 0 until machoFiles.count()) {
        val machoFile: MachoFile = machoFiles.elementAt(index)
        val result = machoFile.ComputeHash(alg)
        Assertions.assertEquals(expectedResult.elementAt(index), result.ConvertToHexString().uppercase())
      }
    }
  }

  companion object {
    @JvmStatic
    fun MachoComputeHashTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("addhoc", "SHA1", listOf("B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")),
        Arguments.of("addhoc_resigned", "SHA1", listOf("B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")),
        Arguments.of("notsigned", "SHA1", listOf("B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")),
        Arguments.of("nosigned_resigned", "SHA1", listOf("B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")),
        Arguments.of(
          "fat.dylib",
          "SHA1",
          listOf("30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")
        ),
        Arguments.of(
          "fat.dylib_signed",
          "SHA1",
          listOf("30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")
        )
      )
    }
  }
}