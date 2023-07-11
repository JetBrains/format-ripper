package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.signatureverifier.serialization.FatMachoFileInfo
import com.jetbrains.signatureverifier.serialization.MachoFileInfo
import com.jetbrains.util.TestUtil
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.*
import java.util.stream.Stream
import kotlin.io.path.copyTo
import kotlin.io.path.deleteExisting

class MachoSignatureStoringTests {

  @ParameterizedTest
  @MethodSource("MachoProvider")
  fun InsertSignatureTest(signedResourceName: String, unsignedResourceName: String) {
    Assertions.assertNotEquals(
      Files.mismatch(
        TestUtil.getTestDataFile("mach-o", signedResourceName),
        TestUtil.getTestDataFile("mach-o", unsignedResourceName)
      ),
      -1
    )

    val machoArch: MachoArch
    val signedSize: Long

    val machoFiles =
      Files.newByteChannel(TestUtil.getTestDataFile("mach-o", signedResourceName), StandardOpenOption.READ).use {
        machoArch = MachoArch(it)
        signedSize = it.size()
        machoArch.Extract()
      }

    val path = TestUtil.getTestDataFile("mach-o", unsignedResourceName)
    val tmpName = "tmp" + Random().nextInt().toString()
    val tmpFile = path.parent.resolve(tmpName)
    path.copyTo(tmpFile)

    if (machoFiles.size == 1) {
      val machoFile = machoFiles.first()

      val fileInfo = MachoFileInfo(machoFile)
      val json = Json.encodeToString(fileInfo)
      val decoded: MachoFileInfo = Json.decodeFromString(json)

      TestUtil.getTestByteChannel("mach-o", tmpName, write = true).use { unsignedStream ->
        decoded.modifyFile(unsignedStream)

        println(tmpFile)
      }
    } else {
      val fatMachoFileInfo = FatMachoFileInfo(
        signedSize,
        machoArch.fatHeaderInfo,
        machoFiles.map { machoFile ->
          MachoFileInfo(machoFile)
        }
      )

      val json = Json.encodeToString(fatMachoFileInfo)
      val decoded: FatMachoFileInfo = Json.decodeFromString(json)
      TestUtil.getTestByteChannel("mach-o", tmpName, write = true).use { unsignedStream ->
        decoded.modifyFile(unsignedStream)

        println(tmpFile)
      }
    }

    Assertions.assertEquals(
      -1,
      Files.mismatch(
        TestUtil.getTestDataFile("mach-o", signedResourceName),
        TestUtil.getTestDataFile("mach-o", tmpName)
      )
    )
    tmpFile.deleteExisting()
  }

  companion object {
    @JvmStatic
    fun MachoProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("addhoc_resigned", "addhoc"),
        Arguments.of("nosigned_resigned", "notsigned"),
        Arguments.of("fat.dylib_signed", "fat.dylib"),
      )
    }
  }

}