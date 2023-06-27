package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.cf.CompoundFile
import com.jetbrains.signatureverifier.cf.DirectoryEntry
import com.jetbrains.signatureverifier.cf.MsiFile
import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
class MsiFileInfo(
  val signedDataInfo: SignedDataInfo,
  val compoundFileMetaInfo: CompoundFile.Companion.CompoundFileMetaInfo,
  val entries: List<DirectoryEntry>,
  @Serializable(ByteArraySerializer::class)
  val rootEntryData: ByteArray?,
  @Serializable(ByteArraySerializer::class)
  val digitalSignatureExData: ByteArray?,
) {
  fun modifyFile(stream: SeekableByteChannel) {
    val signature = signedDataInfo.toSignature()

    val unsignedEntries =
      MsiFile(stream).getEntries()
        .filterNot { MsiFile.hexNamesSet.contains(it.first.Name.toHexString()) }
        .associateBy { it.first.Name.toHexString() }.toMutableMap()

    val unsignedFile = MsiFile(compoundFileMetaInfo, stream)

    val signedEntriesDataMap = mapOf(
      MsiFile.rootEntryName.toHexString() to rootEntryData,
      MsiFile.msiDigitalSignatureExEntryName.toHexString() to digitalSignatureExData,
      MsiFile.digitalSignatureEntryName.toHexString() to signature
    )

    unsignedFile.putEntries(
      entries.map { entry ->
        entry.Name.toHexString().let { name ->
          unsignedEntries[name]?.second?.let { data -> Pair(entry, data) }
            ?: Pair(entry, signedEntriesDataMap[name]!!)
        }
      }
    )
  }
}