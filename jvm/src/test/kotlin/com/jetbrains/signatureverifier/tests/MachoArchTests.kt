package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.macho.MachoConsts
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.stream.Stream

class MachoArchTests {
  @ParameterizedTest
  @MethodSource("MachoArchExtractTestProvider")
  fun MachoArchExtractTest(machoResourceName: String, expHeader1: Long, expHeader2: Long?) {
    val result =
      Files.newByteChannel(TestUtil.getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ).use {
        MachoArch(it).Extract()
      }

    val expectedMachoItems = mutableListOf(expHeader1)

    if (expHeader2 != null)
      expectedMachoItems.add(expHeader2)

    Assertions.assertEquals(expectedMachoItems, result.map { it.Magic })
  }

  companion object {
    @JvmStatic
    fun MachoArchExtractTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("fat.dylib", MachoConsts.MH_MAGIC_64, MachoConsts.MH_MAGIC),
        Arguments.of("x64.dylib", MachoConsts.MH_MAGIC_64, null),
        Arguments.of("x86.dylib", MachoConsts.MH_MAGIC, null),
        Arguments.of("fat.bundle", MachoConsts.MH_MAGIC, MachoConsts.MH_MAGIC_64),
        Arguments.of("x64.bundle", MachoConsts.MH_MAGIC_64, null),
        Arguments.of("x86.bundle", MachoConsts.MH_MAGIC, null),
        Arguments.of("libSystem.Net.Security.Native.dylib", MachoConsts.MH_MAGIC_64, null),
        Arguments.of("env-wrapper.x64", MachoConsts.MH_MAGIC_64, null),
        Arguments.of("libMonoSupportW.x64.dylib", MachoConsts.MH_MAGIC_64, null),
        Arguments.of("cat", MachoConsts.MH_MAGIC_64, MachoConsts.MH_MAGIC_64)
      )
    }
  }
}