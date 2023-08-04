package com.jetbrains.signatureverifier.serialization.fileInfos

import kotlinx.serialization.Serializable

@Serializable
sealed class LoadCommandInfo {
  abstract val offset: Long
  abstract val command: UInt
  abstract val commandSize: UInt

  abstract fun toByteArray(): ByteArray
}