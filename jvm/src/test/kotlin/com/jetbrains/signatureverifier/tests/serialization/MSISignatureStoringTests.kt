package com.jetbrains.signatureverifier.tests.serialization

import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.MsiFileInfo
import com.jetbrains.signatureverifier.serialization.SignedDataInfo
import com.jetbrains.signatureverifier.serialization.compareBytes
import com.jetbrains.signatureverifier.serialization.toHexString
import com.jetbrains.util.Rewind
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

  fun mergeSegments(segments: MutableList<Pair<Int, Int>>): MutableList<Pair<Int, Int>> {
    if (segments.size <= 1) return segments

    // Sort the segments by first element of pair.
    segments.sortBy { it.first }

    val result = mutableListOf<Pair<Int, Int>>()
    result.add(segments[0])

    for (i in 1 until segments.size) {
      // If current segment's start is less than or equal to previous segment's end, then update previous segment's end
      if (result.last().second >= segments[i].first) {
        val lastElement = result.removeLast()
        result.add(Pair(lastElement.first, lastElement.second.coerceAtLeast(segments[i].second)))
      } else {
        result.add(segments[i]) // Otherwise, add current segment as separate.
      }
    }
    return result
  }

  fun findGaps(start: Int, end: Int, segments: List<Pair<Int, Int>>): List<Pair<Int, Int>> {
    val gaps = mutableListOf<Pair<Int, Int>>()
    var currStart = start

    for ((segStart, segEnd) in segments) {
      if (segStart > currStart) {
        gaps.add(Pair(currStart - 1, segStart))
      }
      currStart = (segEnd).coerceAtLeast(currStart)
    }

    if (currStart <= end) {
      gaps.add(Pair(currStart, end))
    }

    return gaps
  }

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

      val visitedSegments = mutableListOf<Pair<Int, Int>>()
      val signedEntriesData =
        signedFile.getEntries(visitedSegments)//.filterNot { MsiFile.hexNamesSet.contains(it.first.Name.toHexString()) }
      val rootSegments = mutableListOf<Pair<Int, Int>>()
      val rootEntry = signedFile.getRootEntry(rootSegments).second
      val mergedSegments =
        mergeSegments(visitedSegments.slice(rootSegments.size until visitedSegments.size).toMutableList())
      val mergedRootSegments = mergeSegments(rootSegments)
      Assertions.assertEquals(1, mergedRootSegments.size)
      val mergedRootSegment = mergedRootSegments.first()

      val specialSegments =
        findGaps(mergedRootSegment.first, mergedRootSegment.second,
          mergedSegments.filter { it.first >= mergedRootSegment.first && it.second <= mergedRootSegment.second })
          .map { range ->
            range.first to rootEntry.sliceArray(range.first - mergedRootSegment.first until range.second - mergedRootSegment.first)
          }

      val signedEntriesDataMap = signedEntriesData.associateBy { it.first.Name.toHexString() }

      val specialEntries = listOfNotNull(
        null,
        signedEntriesDataMap["40483F3BF2433844B145"],
        signedEntriesDataMap["40483F3F77456C446A3EB2442F48"],
      )

      val msiFileInfo = MsiFileInfo(
        signedDataInfo,
        cfMetaInfo,
        signedEntriesData.map { it.first },
        specialEntries,
        specialSegments,
        signedEntriesDataMap[MsiFile.rootEntryName.toHexString()]?.second,
        signedEntriesDataMap[MsiFile.msiDigitalSignatureExEntryName.toHexString()]?.second,
        signedEntriesDataMap[MsiFile.rootEntryName.toHexString()]!!.first.StartSect.toInt()
      )

      val json = Json.encodeToString(msiFileInfo)
      val decoded: MsiFileInfo = Json.decodeFromString(json)

      val path = TestUtil.getTestDataFile("msi", unsignedResourceName)
      val tmpName = "tmp" + Random().nextInt().toString()
      val tmpFile = path.parent.resolve(tmpName)
      path.copyTo(tmpFile)

      TestUtil.getTestByteChannel("msi", tmpName, write = true).use { unsignedStream ->
//        var unsignedEntries = MsiFile(unsignedStream).getEntries().associateBy { it.first.Name.toHexString() }

        decoded.modifyFile(unsignedStream)

        unsignedStream.Rewind()
//
        val unsignedFile = MsiFile(unsignedStream)
        val unsignedEntries = unsignedFile.getEntries().associateBy { it.first.Name.toHexString() }
//
//
        signedEntriesData.forEach { entry ->
          try {
            if (!compareBytes(
                entry.second,
                unsignedEntries[entry.first.Name.toHexString()]!!.second,
                verbose = false
              )
            ) {
              println(entry.first.Name.toHexString())
              compareBytes(entry.second, unsignedEntries[entry.first.Name.toHexString()]!!.second, verbose = false)
              println()
            }
          } catch (_: Exception) {
          }
        }
//
//
        println(tmpName)
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