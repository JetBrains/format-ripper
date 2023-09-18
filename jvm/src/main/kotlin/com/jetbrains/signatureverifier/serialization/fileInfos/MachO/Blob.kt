package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.macho.CSMAGIC
import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import com.jetbrains.signatureverifier.serialization.toByteArray
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
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as Blob

    if (type != other.type) return false
    if (offset != other.offset) return false
    if (magic != other.magic) return false
    if (magicValue != other.magicValue) return false
    if (length != other.length) return false
    if (!content.contentEquals(other.content)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = type.hashCode()
    result = 31 * result + offset.hashCode()
    result = 31 * result + magic.hashCode()
    result = 31 * result + magicValue.hashCode()
    result = 31 * result + length
    result = 31 * result + content.contentHashCode()
    return result
  }
}