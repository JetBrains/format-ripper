package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

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

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as LoadCommandLinkeditInfo

    if (offset != other.offset) return false
    if (command != other.command) return false
    if (commandSize != other.commandSize) return false
    if (!segmentName.contentEquals(other.segmentName)) return false
    if (vmAddress != other.vmAddress) return false
    if (vmSize != other.vmSize) return false
    if (vmFileOff != other.vmFileOff) return false
    if (fileSize != other.fileSize) return false
    if (vmProcMaximumProtection != other.vmProcMaximumProtection) return false
    if (vmProcInitialProtection != other.vmProcInitialProtection) return false
    if (sectionsNum != other.sectionsNum) return false
    if (segmentFlags != other.segmentFlags) return false

    return true
  }

  override fun hashCode(): Int {
    var result = offset.hashCode()
    result = 31 * result + command.hashCode()
    result = 31 * result + commandSize.hashCode()
    result = 31 * result + segmentName.contentHashCode()
    result = 31 * result + vmAddress.hashCode()
    result = 31 * result + vmSize.hashCode()
    result = 31 * result + vmFileOff.hashCode()
    result = 31 * result + fileSize.hashCode()
    result = 31 * result + vmProcMaximumProtection.hashCode()
    result = 31 * result + vmProcInitialProtection.hashCode()
    result = 31 * result + sectionsNum.hashCode()
    result = 31 * result + segmentFlags.hashCode()
    return result
  }
}