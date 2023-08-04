package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.dataholders.SignedDataInfo
import com.jetbrains.signatureverifier.serialization.findGaps
import com.jetbrains.signatureverifier.serialization.mergeSegments
import com.jetbrains.signatureverifier.serialization.toHexString
import kotlinx.serialization.Serializable

@Serializable
class MsiFileInfo : FileInfo {
  override val signedDataInfo: SignedDataInfo
  override val fileMetaInfo: MsiFileMetaInfo

  constructor(msiFile: MsiFile) {
    val cfMetaInfo = msiFile.getCFMetaInfo()

    // Extract signature
    val signatureData = msiFile.GetSignatureData()
    val signedMessage = SignedMessage.CreateInstance(signatureData)
    val signedData = signedMessage.SignedData
    signedDataInfo = SignedDataInfo(signedData)

    // Read segments, that should be written as is
    val visitedSegments = mutableListOf<Pair<Int, Int>>()
    val signedEntriesData =
      msiFile.getEntries(visitedSegments)

    val rootSegments = mutableListOf<Pair<Int, Int>>()
    val rootEntry = msiFile.getRootEntry(rootSegments)

    val mergedSegments =
      mergeSegments(visitedSegments.slice(rootSegments.size until visitedSegments.size).toMutableList())
    val mergedRootSegments = mergeSegments(rootSegments)
    val mergedRootSegment = mergedRootSegments.first()

    val specialSegments =
      findGaps(mergedRootSegment.first, mergedRootSegment.second,
        mergedSegments.filter { it.first >= mergedRootSegment.first && it.second <= mergedRootSegment.second })
        .map { range ->
          range.first to rootEntry.second.sliceArray(range.first - mergedRootSegment.first until range.second - mergedRootSegment.first)
        }

    val signedEntriesDataMap = signedEntriesData.associateBy { it.first.Name.toHexString() }

    fileMetaInfo = MsiFileMetaInfo(
      msiFile.fileSize,
      cfMetaInfo,
      signedEntriesData.map { it.first },
      MsiFileMetaInfo.knownSpecialEntryNames.map {
        signedEntriesDataMap[it]
      }.filterNotNull().map { it.first.Name.toHexString() to it.second },
      specialSegments,
      signedEntriesDataMap[MsiFile.msiDigitalSignatureExEntryName.toHexString()]?.second,
      rootEntry.first.StartSect.toInt()
    )
  }
}