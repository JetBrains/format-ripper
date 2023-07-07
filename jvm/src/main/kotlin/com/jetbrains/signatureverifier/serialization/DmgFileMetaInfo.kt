package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.dmg.DmgFile
import com.jetbrains.signatureverifier.macho.CSMAGIC
import com.jetbrains.signatureverifier.macho.MachoConsts
import com.jetbrains.util.*
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
data class DmgFileMetaInfo(
  val fileSize: Long,
  val codeSignaturePointer: DmgFile.CodeSignaturePointer,
  val codeSignatureInfo: CodeSignatureInfo = CodeSignatureInfo()
) : FileMetaInfo {
  override fun modifyFile(stream: SeekableByteChannel, signature: ByteArray) {
    val reader = BinaryReader(stream.Rewind())
    stream.Jump(stream.size() - DmgFile.UDIFResourceFileSize)
    val unsignedUDIFResourceFile = reader.ReadBytes(DmgFile.UDIFResourceFileSize)

    stream.Seek(0, SeekOrigin.End)
    if (fileSize > stream.size()) {
      stream.write(ByteBuffer.wrap(ByteArray((fileSize - stream.size()).toInt() + 1)))
    }

    stream.Jump(codeSignaturePointer.offset)
    stream.write(ByteBuffer.wrap(codeSignatureInfo.toByteArray()))
    codeSignatureInfo.blobs.forEach {
      stream.Jump(codeSignatureInfo.superBlobStart)
      stream.Seek(it.offset.toLong(), SeekOrigin.Current)

      it.length += 2 * UInt.SIZE_BYTES // in dmg `length` includes magicValue and length

      if (it.magic == CSMAGIC.CMS_SIGNATURE) {
        it.content = signature
      }

      if (it.type.toLong() == MachoConsts.CSSLOT_CODEDIRECTORY) {
        stream.write(ByteBuffer.wrap(it.content))
      } else {
        stream.write(ByteBuffer.wrap(it.toByteArray()))
      }
    }

    stream.Jump(stream.size() - DmgFile.UDIFResourceFileSize)
    stream.write(ByteBuffer.wrap(unsignedUDIFResourceFile))

    stream.Jump(stream.size() - DmgFile.UDIFResourceFileSize + DmgFile.codeSignaturePointerOffset)
    stream.write(ByteBuffer.wrap(codeSignaturePointer.toByteArray()))
  }
}