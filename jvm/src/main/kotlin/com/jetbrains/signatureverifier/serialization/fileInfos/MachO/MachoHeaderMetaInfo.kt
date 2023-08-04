package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

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