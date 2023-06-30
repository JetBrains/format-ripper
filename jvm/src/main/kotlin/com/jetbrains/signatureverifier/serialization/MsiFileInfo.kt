package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.cf.CompoundFile
import com.jetbrains.signatureverifier.cf.DirectoryEntry
import com.jetbrains.signatureverifier.cf.MsiFile
import com.jetbrains.util.Jump
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
class MsiFileInfo(
  override val signedDataInfo: SignedDataInfo,
  private val compoundFileMetaInfo: CompoundFile.Companion.CompoundFileMetaInfo,
  private val entries: List<DirectoryEntry>,
  private val specialEntries: List<Pair<String, @Serializable(ByteArraySerializer::class) ByteArray>>,
  private val specialSegments: List<Pair<Int, @Serializable(ByteArraySerializer::class) ByteArray>>,
  @Serializable(ByteArraySerializer::class)
  val digitalSignatureExData: ByteArray?,
  private val miniStreamStartSector: Int
) : FileInfo {
  companion object {
    // Those entries vary between signed and unsigned files, but are not logically related to signature
    val knownSpecialEntryNames = listOf("40483F3BF2433844B145", "40483F3F77456C446A3EB2442F48")
  }

  override fun modifyFile(stream: SeekableByteChannel) {
    val signature = signedDataInfo.toSignature()

    var unsignedFile = MsiFile(stream)

    val unsignedEntries = unsignedFile.getEntries()
    val unsignedEntriesMap =
      unsignedEntries
        .associateBy { it.first.Name.toHexString() }

    val startSect = unsignedEntriesMap[MsiFile.rootEntryName.toHexString()]!!.first.StartSect

    unsignedFile.putEntries(
      unsignedEntries,
      startSect.toInt(),
      wipe = true
    )

    unsignedFile = MsiFile(compoundFileMetaInfo, stream)

    val specialEntriesDataMap = mutableMapOf(
      MsiFile.msiDigitalSignatureExEntryName.toHexString() to digitalSignatureExData,
      MsiFile.digitalSignatureEntryName.toHexString() to signature
    )
    specialEntriesDataMap.putAll(specialEntries)


    unsignedFile.putEntries(
      entries.map { entry ->
        entry.Name.toHexString().let { name ->
          specialEntriesDataMap[name]?.let { Pair(entry, it) } ?: Pair(entry, unsignedEntriesMap[name]!!.second)
        }
      },
      miniStreamStartSector
    )

    specialSegments.forEach {
      stream.Jump(it.first.toUInt())
      stream.write(ByteBuffer.wrap(it.second))
    }
  }
}