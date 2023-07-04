package com.jetbrains.signatureverifier.serialization

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
}