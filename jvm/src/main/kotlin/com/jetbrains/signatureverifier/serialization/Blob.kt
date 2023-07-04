package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.macho.CSMAGIC
import kotlinx.serialization.Serializable

@Serializable
data class Blob(
  val type: UInt = 0u,
  val offset: UInt = 0u,
  val magic: CSMAGIC = CSMAGIC.UNKNOWN,
  val magicValue: UInt = 0u,
  var length: Int = 0,
  @Serializable(ByteArraySerializer::class)
  var content: ByteArray = byteArrayOf()
) {
  constructor(type: UInt, offset: UInt, magic: CSMAGIC, magicValue: UInt, content: ByteArray) : this(
    type, offset, magic, magicValue, content.size, content
  )

  fun toByteArray() = magicValue.toByteArray(true) + length.toByteArray(true) + content
}