package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.dmg.DmgFile
import com.jetbrains.signatureverifier.serialization.fileInfos.DmgFileInfo
import com.jetbrains.signatureverifier.serialization.fileInfos.SignedDataInfo
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

class DmgSignatureStoringTests {

  @ParameterizedTest
  @MethodSource("InsertSignatureTestProvider")
  fun InsertSignatureTest(signedResourceName: String, unsignedResourceName: String) {
    Assertions.assertNotEquals(
      Files.mismatch(
        TestUtil.getTestDataFile("dmg", signedResourceName),
        TestUtil.getTestDataFile("dmg", unsignedResourceName)
      ),
      -1
    )

    val fileInfo: DmgFileInfo
    TestUtil.getTestByteChannel("dmg", signedResourceName, write = false).use {
      val signedFile = DmgFile(it)
      val signatureData = signedFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedData = signedMessage.SignedData
      val signedDataInfo = SignedDataInfo(signedData)

      fileInfo = DmgFileInfo(signedFile.getMetaInfo(), signedDataInfo)
    }

    val json = Json.encodeToString(fileInfo)
    val decoded: DmgFileInfo = Json.decodeFromString(json)

    val path = TestUtil.getTestDataFile("dmg", unsignedResourceName)
    val tmpName = "tmp" + Random().nextInt().toString()
    val tmpFile = path.parent.resolve(tmpName)
    path.copyTo(tmpFile)

    TestUtil.getTestByteChannel("dmg", tmpName, write = true).use {
      decoded.modifyFile(it)
    }

    println(tmpName)
    Assertions.assertEquals(
      -1,
      Files.mismatch(
        TestUtil.getTestDataFile("dmg", signedResourceName),
        TestUtil.getTestDataFile("dmg", tmpName)
      )
    )
    tmpFile.deleteExisting()

  }

  companion object {
    @JvmStatic
    fun InsertSignatureTestProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("steam.dmg", "steam_not_signed.dmg"),
        Arguments.of("dd.dmg", "dd_not_signed.dmg")
      )
    }
  }
}