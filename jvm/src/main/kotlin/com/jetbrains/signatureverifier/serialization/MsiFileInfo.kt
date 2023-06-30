package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.cf.CompoundFile
import com.jetbrains.signatureverifier.cf.DirectoryEntry
import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.util.Jump
import com.jetbrains.util.Rewind
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
class MsiFileInfo(
  override val signedDataInfo: SignedDataInfo,
  val compoundFileMetaInfo: CompoundFile.Companion.CompoundFileMetaInfo,
  val entries: List<DirectoryEntry>,
  val specialEntries: List<Pair<DirectoryEntry, ByteArray>>,
  val specialSegments: List<Pair<Int, ByteArray>>,
  @Serializable(ByteArraySerializer::class)
  val rootEntryData: ByteArray?,
  @Serializable(ByteArraySerializer::class)
  val digitalSignatureExData: ByteArray?,
  val miniStreamStartSector: Int
) : FileInfo {
  override fun modifyFile(stream: SeekableByteChannel) {
    val signature = signedDataInfo.toSignature()

    var unsignedFile = MsiFile(stream)

    val unsignedEntries = unsignedFile.getEntries()
    val startSect =
      unsignedEntries.find { it.first.Name.toHexString() == MsiFile.rootEntryName.toHexString() }!!.first.StartSect

    unsignedFile.putEntries(
      unsignedEntries,
      startSect.toInt(),
      wipe = true
//      dirIndex
    )

    stream.Rewind()

    val entriesMap = entries.associateBy { it.Name.toHexString() }
    val oddEntries =
      unsignedEntries.filterNot { entriesMap.contains(it.first.Name.toHexString()) }.filter { it.second.isNotEmpty() }
    val unsignedEntriesMap =
      unsignedEntries
//        .filterNot { MsiFile.hexNamesSet.contains(it.first.Name.toHexString()) }
        .associateBy { it.first.Name.toHexString() }

    unsignedFile = MsiFile(compoundFileMetaInfo, stream)
    stream.Rewind()

    val specialEntriesDataMap = mutableMapOf(
      MsiFile.rootEntryName.toHexString() to rootEntryData,
      MsiFile.msiDigitalSignatureExEntryName.toHexString() to digitalSignatureExData,
      MsiFile.digitalSignatureEntryName.toHexString() to signature
    )
    specialEntries.forEach {
      specialEntriesDataMap[it.first.Name.toHexString()] = it.second
    }


    unsignedFile.putEntries(
      entries.map { entry ->
        entry.Name.toHexString().let { name ->
          if (specialEntriesDataMap.containsKey(name)) {
            Pair(entry, specialEntriesDataMap[name]!!)
          } else {
            unsignedEntriesMap[name]!!.second.let { data -> Pair(entry, data) }
          }
        }
      },//.filter { it.second.isNotEmpty() },
      miniStreamStartSector,
//      dirIndex
    )

    specialSegments.forEach {
      stream.Jump(it.first.toUInt())
      stream.write(ByteBuffer.wrap(it.second))
    }
  }
}