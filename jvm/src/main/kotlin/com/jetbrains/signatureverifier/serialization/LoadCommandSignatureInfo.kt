package com.jetbrains.signatureverifier.serialization

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