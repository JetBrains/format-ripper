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

    TestUtil.getTestByteChannel("msi", signedResourceName, write = false).use {
      signedFile = MsiFile(it)
      val cfMetaInfo = signedFile.getCFMetaInfo()

      // Extract signature
      val signatureData = signedFile.GetSignatureData()
      val signedMessage = SignedMessage.CreateInstance(signatureData)
      val signedData = signedMessage.SignedData
      val signedDataInfo = SignedDataInfo(signedData)

      // Read segments, that should be written as is
      val visitedSegments = mutableListOf<Pair<Int, Int>>()
      val signedEntriesData =
        signedFile.getEntries(visitedSegments)

      val rootSegments = mutableListOf<Pair<Int, Int>>()
      val rootEntry = signedFile.getRootEntry(rootSegments)

      val mergedSegments =
        mergeSegments(visitedSegments.slice(rootSegments.size until visitedSegments.size).toMutableList())
      val mergedRootSegments = mergeSegments(rootSegments)
      Assertions.assertEquals(1, mergedRootSegments.size)
      val mergedRootSegment = mergedRootSegments.first()

      val specialSegments =
        findGaps(mergedRootSegment.first, mergedRootSegment.second,
          mergedSegments.filter { it.first >= mergedRootSegment.first && it.second <= mergedRootSegment.second })
          .map { range ->
            range.first to rootEntry.second.sliceArray(range.first - mergedRootSegment.first until range.second - mergedRootSegment.first)
          }

      val signedEntriesDataMap = signedEntriesData.associateBy { it.first.Name.toHexString() }

      val msiFileInfo = MsiFileInfo(
        signedDataInfo,
        cfMetaInfo,
        signedEntriesData.map { it.first },
        MsiFileInfo.knownSpecialEntryNames.map {
          signedEntriesDataMap[it]
        }.filterNotNull().map { it.first.Name.toHexString() to it.second },
        specialSegments,
        signedEntriesDataMap[MsiFile.msiDigitalSignatureExEntryName.toHexString()]?.second,
        rootEntry.first.StartSect.toInt()
      )

      val json = Json.encodeToString(msiFileInfo)
      val decoded: MsiFileInfo = Json.decodeFromString(json)

      val path = TestUtil.getTestDataFile("msi", unsignedResourceName)
      val tmpName = "tmp" + Random().nextInt().toString()
      val tmpFile = path.parent.resolve(tmpName)
      path.copyTo(tmpFile)

      TestUtil.getTestByteChannel("msi", tmpName, write = true).use { unsignedStream ->
        decoded.modifyFile(unsignedStream)

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
        Arguments.of("firefox.msi", "firefox_not_signed.msi"),
        Arguments.of("sumatra.msi", "sumatra_not_signed.msi"),
      )
    }
  }

}