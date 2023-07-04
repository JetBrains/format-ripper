package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable

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