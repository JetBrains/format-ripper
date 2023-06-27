package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.*
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
    val unsignedFile: MsiFile

    TestUtil.getTestByteChannel("msi", signedResourceName, write = false).use {
      signedFile = MsiFile(it)
      val cfMetaInfo = signedFile.getCFMetaInfo()

      val signatureData = signedFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedData = signedMessage.SignedData
      val signedDataInfo = SignedDataInfo(signedData)
      val signedEntriesData = signedFile.getEntries().filter { entry -> entry.second.isNotEmpty() }//.map { it.first }
      val signedEntriesDataMap = signedEntriesData.associateBy { it.first.Name.toHexString() }

      val msiInfo = MSIInfo(
        signedDataInfo,
        cfMetaInfo,
        signedEntriesData.map { it.first },
        signedEntriesDataMap[MsiFile.rootEntryName.toHexString()]?.second,
        signedEntriesDataMap[MsiFile.msiDigitalSignatureExEntryName.toHexString()]?.second
      )
      val json = Json.encodeToString(msiInfo)
      val decoded: MSIInfo = Json.decodeFromString(json)

      val path = TestUtil.getTestDataFile("msi", unsignedResourceName)
      val tmpName = "tmp" + Random().nextInt().toString()
      val tmpFile = path.parent.resolve(tmpName)
      path.copyTo(tmpFile)


      TestUtil.getTestByteChannel("msi", tmpName, write = true).use { unsignedStream ->

        decoded.modifyFile(unsignedStream)
        Assertions.assertEquals(
          Files.mismatch(
            TestUtil.getTestDataFile("msi", signedResourceName),
            TestUtil.getTestDataFile("msi", tmpName)
          ),
          -1
        )
      }
      tmpFile.deleteExisting()
    }


    println()
  }

  companion object {
    @JvmStatic
    fun MsiProvider(): Stream<Arguments> {
      return Stream.of(
        Arguments.of("2dac4b.msi", "2dac4b_not_signed.msi"),
        Arguments.of("firefox.msi", "firefox_not_signed.msi"),
      )
    }
  }

}