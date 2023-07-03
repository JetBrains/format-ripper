package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.macho.MachoConsts
import com.jetbrains.util.Jump
import com.jetbrains.util.Rewind
import com.jetbrains.util.Seek
import com.jetbrains.util.SeekOrigin
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

@Serializable
data class MachoFileMetaInfo(
  var fileSize: Long = 0L,
  var isBe: Boolean = false,
  var headerMetaInfo: MachoHeaderMetaInfo = MachoHeaderMetaInfo(),
  val loadCommands: MutableList<LoadCommandInfo> = mutableListOf(),
  val codeSignatureInfo: CodeSignatureInfo = CodeSignatureInfo()
) : FileMetaInfo {

  @Serializable
  data class MachoHeaderMetaInfo(
    val magic: UInt = 0u,
    val cpuType: UInt = 0u,
    val cpuSubType: UInt = 0u,
    val fileType: UInt = 0u,
    val numLoadCommands: UInt = 0u,
    val sizeLoadCommands: UInt = 0u,
    val flags: UInt = 0u,
    val reserved: UInt = 0u,
  ) {
    fun toByteArray(isBe: Boolean): ByteArray =
      magic.toByteArray(isBe) +
        cpuType.toByteArray(isBe) +
        cpuSubType.toByteArray(isBe) +
        fileType.toByteArray(isBe) +
        numLoadCommands.toByteArray(isBe) +
        sizeLoadCommands.toByteArray(isBe) +
        flags.toByteArray(isBe) +
        reserved.toByteArray(isBe)
  }

  @Serializable
  sealed class LoadCommandInfo {
    abstract val offset: Long
    abstract val command: UInt
    abstract val commandSize: UInt

    abstract fun toByteArray(): ByteArray
  }

  @Serializable
  data class LoadCommandSignatureInfo(
    override val offset: Long,
    override val command: UInt,
    override val commandSize: UInt,
    val dataOffset: UInt,
    val dataSize: UInt
  ) : LoadCommandInfo() {
    override fun toByteArray(): ByteArray =
      command.toByteArray() +
        commandSize.toByteArray() +
        dataOffset.toByteArray() +
        dataSize.toByteArray()
  }


  @Serializable
  data class LoadCommandLinkeditInfo(
    override val offset: Long,
    override val command: UInt,
    override val commandSize: UInt,
    @Serializable(ByteArraySerializer::class)
    val segmentName: ByteArray,
    val vmAddress: ULong,
    val vmSize: ULong,
    val vmFileOff: ULong,
    val fileSize: ULong,
    val vmProcMaximumProtection: UInt,
    val vmProcInitialProtection: UInt,
    val sectionsNum: UInt,
    val segmentFlags: UInt
  ) : LoadCommandInfo() {
    override fun toByteArray(): ByteArray =
      command.toByteArray() +
        commandSize.toByteArray() +
        segmentName +
        vmAddress.toLong().toByteArray() +
        vmSize.toLong().toByteArray() +
        vmFileOff.toLong().toByteArray() +
        fileSize.toLong().toByteArray() +
        vmProcMaximumProtection.toByteArray(true) +
        vmProcInitialProtection.toByteArray(true) +
        sectionsNum.toByteArray(true) +
        segmentFlags.toByteArray(true)
  }

  @Serializable
  data class CodeSignatureInfo(
    var magic: UInt = 0u,
    var length: UInt = 0u,
    var superBlobStart: Long = 0L,
    var superBlobCount: Int = 0,
    var blobs: MutableList<Blob> = mutableListOf()
  ) {
    fun toByteArray() =
      magic.toByteArray(true) + length.toByteArray(true) + blobs.count().toByteArray(true) +
        blobs.fold(byteArrayOf()) { acc, it -> acc + it.type.toByteArray(true) + it.offset.toByteArray(true) }
  }

  @Serializable
  data class Blob(
    val type: UInt = 0u,
    val offset: UInt = 0u,
    var magic: UInt = 0u,
    var length: Int = 0,
    @Serializable(ByteArraySerializer::class)
    var content: ByteArray = byteArrayOf(),
    val isSignature: Boolean = false
  ) {
    constructor(type: UInt, offset: UInt, magic: UInt, content: ByteArray) : this(
      type, offset, magic, content.size, content
    )

    fun toByteArray() = magic.toByteArray(true) + length.toByteArray(true) + content
  }

  override fun modifyFile(stream: SeekableByteChannel, signature: ByteArray) {
    stream.Rewind()
    stream.write(ByteBuffer.wrap(headerMetaInfo.toByteArray(isBe)))

    loadCommands.forEach {
      stream.Jump(it.offset)
      stream.write(ByteBuffer.wrap(it.toByteArray()))
    }

    stream.Jump(codeSignatureInfo.superBlobStart)
    stream.write(ByteBuffer.wrap(codeSignatureInfo.toByteArray()))
    codeSignatureInfo.blobs.forEach {
      stream.Seek(codeSignatureInfo.superBlobStart, SeekOrigin.Begin)
      stream.Seek(it.offset.toLong(), SeekOrigin.Current)

      if (it.isSignature) {
        it.magic = MachoConsts.CSMAGIC_CMS_SIGNATURE.toUInt()
        it.length = signature.size + 8
        it.content = signature
      }
      if (it.type.toLong() == MachoConsts.CSSLOT_CODEDIRECTORY) {
        stream.write(ByteBuffer.wrap(it.content))
      } else {
        stream.write(ByteBuffer.wrap(it.toByteArray()))
      }
    }

    if (fileSize < stream.size()) {
      stream.truncate(fileSize)
    } else if (fileSize > stream.size()) {
      stream.write(ByteBuffer.wrap(ByteArray((fileSize - stream.size()).toInt())))
    }
  }
}