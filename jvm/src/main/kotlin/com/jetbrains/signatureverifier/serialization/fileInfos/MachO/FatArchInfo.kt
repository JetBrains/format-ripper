package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

@Serializable
sealed class FatArchInfo {
  abstract val cpuType: UInt
  abstract val cpuSubType: UInt

  abstract fun toByteArray(isBe: Boolean): ByteArray
}

@Serializable
data class FatArchInfo64(
  override val cpuType: UInt,
  override val cpuSubType: UInt,
  val fileOffset: ULong,
  val size: ULong,
  val align: ULong,
) : FatArchInfo() {
  override fun toByteArray(isBe: Boolean) =
    cpuType.toByteArray() +
      cpuSubType.toByteArray() +
      fileOffset.toLong().toByteArray(isBe) +
      size.toLong().toByteArray(isBe) +
      align.toLong().toByteArray(isBe)
}

@Serializable
data class FatArchInfo32(
  override val cpuType: UInt,
  override val cpuSubType: UInt,
  val fileOffset: UInt,
  val size: UInt,
  val align: UInt,
) : FatArchInfo() {
  override fun toByteArray(isBe: Boolean) =
    cpuType.toByteArray() +
      cpuSubType.toByteArray() +
      fileOffset.toByteArray(isBe) +
      size.toByteArray(isBe) +
      align.toByteArray(isBe)
}
