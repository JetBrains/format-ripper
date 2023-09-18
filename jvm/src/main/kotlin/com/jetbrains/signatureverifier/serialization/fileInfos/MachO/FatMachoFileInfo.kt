package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.macho.MachoArch
import com.jetbrains.util.*
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
data class FatMachoFileInfo(
  val size: Long,
  val fatHeaderInfo: FatHeaderInfo,
  val machoFileInfos: List<MachoFileInfo>
) {

  fun modifyFile(stream: SeekableByteChannel) {
    val unsignedFiles = MachoArch(stream).Extract()

    stream.Seek(0, SeekOrigin.End)
    if (size > stream.size()) {
      stream.write(ByteBuffer.wrap(ByteArray((size - stream.size()).toInt() + 1)))
    }

    stream.Rewind()
    stream.write(ByteBuffer.wrap(fatHeaderInfo.toByteArray()))

    val reader = BinaryReader(stream.Rewind())


    unsignedFiles.zip(machoFileInfos).reversed().forEach { (unsignedFile, signedFileInfo) ->
      if (unsignedFile.metaInfo.machoOffset != (signedFileInfo.fileMetaInfo as MachoFileMetaInfo).machoOffset) {
        stream.Jump(unsignedFile.metaInfo.machoOffset)
        val data = reader.ReadBytes(unsignedFile.metaInfo.fileSize.toInt())

        stream.Jump(signedFileInfo.fileMetaInfo.machoOffset)
        stream.write(ByteBuffer.wrap(data))

        stream.Jump(unsignedFile.metaInfo.machoOffset)
        stream.write(ByteBuffer.wrap(ByteArray(data.size)))
      }
    }

    machoFileInfos.forEach {
      it.modifyFile(stream)
    }
  }

}