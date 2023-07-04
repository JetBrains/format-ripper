package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.macho.CSMAGIC
import kotlinx.serialization.Serializable

@Serializable
data class Blob(
  val type: UInt = 0u,
  val offset: UInt = 0u,
  var magic: CSMAGIC = CSMAGIC.UNKNOWN,
  var length: Int = 0,
  @Serializable(ByteArraySerializer::class)
  var content: ByteArray = byteArrayOf()
) {
  constructor(type: UInt, offset: UInt, magic: CSMAGIC, content: ByteArray) : this(
    type, offset, magic, content.size, content
  )

  fun toByteArray() = magic.code.toByteArray(true) + length.toByteArray(true) + content
}