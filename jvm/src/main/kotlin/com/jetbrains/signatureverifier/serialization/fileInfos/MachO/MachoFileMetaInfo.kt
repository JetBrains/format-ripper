package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.macho.CSMAGIC
import com.jetbrains.signatureverifier.macho.MachoConsts
import com.jetbrains.util.Jump
import com.jetbrains.util.Seek
import com.jetbrains.util.SeekOrigin
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
data class MachoFileMetaInfo(
  var machoOffset: Long = 0L,
  var fileSize: Long = 0L,
  var isBe: Boolean = false,
  var headerMetaInfo: MachoHeaderMetaInfo = MachoHeaderMetaInfo(),
  val loadCommands: MutableList<LoadCommandInfo> = mutableListOf(),
  val codeSignatureInfo: CodeSignatureInfo = CodeSignatureInfo()
) : FileMetaInfo {


  override fun modifyFile(stream: SeekableByteChannel, signature: ByteArray) {
    stream.Seek(0, SeekOrigin.End)
    if (fileSize > stream.size()) {
      stream.write(ByteBuffer.wrap(ByteArray((fileSize - stream.size()).toInt() + 1)))
    }

    stream.Jump(machoOffset)

    stream.write(ByteBuffer.wrap(headerMetaInfo.toByteArray(isBe)))

    loadCommands.forEach {
      stream.Jump(it.offset + machoOffset)
      stream.write(ByteBuffer.wrap(it.toByteArray()))
    }

    stream.Jump(codeSignatureInfo.superBlobStart + machoOffset)
    stream.write(ByteBuffer.wrap(codeSignatureInfo.toByteArray()))
    codeSignatureInfo.blobs.forEach {
      stream.Jump(codeSignatureInfo.superBlobStart + machoOffset)
      stream.Seek(it.offset.toLong(), SeekOrigin.Current)

      if (it.magic == CSMAGIC.CMS_SIGNATURE) {
//        it.magic = MachoConsts.CSMAGIC_CMS_SIGNATURE.toUInt()
        it.length = signature.size + 8
        it.content = signature
      }
      if (it.type.toLong() == MachoConsts.CSSLOT_CODEDIRECTORY) {
        stream.write(ByteBuffer.wrap(it.content))
      } else {
        stream.write(ByteBuffer.wrap(it.toByteArray()))
      }
    }

  }
}