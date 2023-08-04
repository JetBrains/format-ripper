package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

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