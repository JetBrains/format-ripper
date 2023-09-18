package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.serialization.fileInfos.MsiFileInfo
import com.jetbrains.util.TestUtil
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.file.Files
import java.util.*
import java.util.stream.Stream
import kotlin.io.path.copyTo
import kotlin.io.path.deleteExisting

class MSISignatureStoringTests {

  @ParameterizedTest
  @MethodSource("MsiProvider")
  fun InsertSignatureTest(signedResourceName: String, unsignedResourceName: String) {
    Assertions.assertNotEquals(
      Files.mismatch(
        TestUtil.getTestDataFile("msi", signedResourceName),
        TestUtil.getTestDataFile("msi", unsignedResourceName)
      ),
      -1
    )

    val signedFile: MsiFile

    TestUtil.getTestByteChannel("msi", signedResourceName, write = false).use {
      signedFile = MsiFile(it)

      val msiFileInfo = MsiFileInfo(signedFile)

      val json = Json.encodeToString(msiFileInfo)
      val decoded: MsiFileInfo = Json.decodeFromString(json)

      val path = TestUtil.getTestDataFile("msi", unsignedResourceName)
      val tmpName = "tmp" + Random().nextInt().toString()
      val tmpFile = path.parent.resolve(tmpName)
      path.copyTo(tmpFile)

      TestUtil.getTestByteChannel("msi", tmpName, write = true).use { unsignedStream ->
        decoded.modifyFile(unsignedStream)

        println(tmpFile)
        Assertions.assertEquals(
          -1,
          Files.mismatch(
            TestUtil.getTestDataFile("msi", signedResourceName),
            TestUtil.getTestDataFile("msi", tmpName)
          )
        )
      }
      tmpFile.deleteExisting()
    }
  }

  companion object {
    @JvmStatic
    fun MsiProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("2dac4b.msi", "2dac4b_not_signed.msi"),
        Arguments.of("2dac4b_signed2.msi", "2dac4b_not_signed.msi"),
        Arguments.of("firefox.msi", "firefox_not_signed.msi"),
        Arguments.of("sumatra.msi", "sumatra_not_signed.msi"),
      )
    }
  }

}