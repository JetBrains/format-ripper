package com.jetbrains.signatureverifier

import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.nio.charset.StandardCharsets

class BinaryReader(private val channel: ByteChannel) {
  /** Reusable buffer */
  private val buffer = ByteBuffer.allocateDirect(8).also { it.order(java.nio.ByteOrder.LITTLE_ENDIAN) }

  val BaseStream: ByteChannel
    get() = channel

  fun ReadUInt32(): UInt {
    fill(4)
    return buffer.int.toUInt()
  }

  fun ReadUInt64(): ULong {
    fill(8)
    return buffer.long.toULong()
  }

  fun ReadInt32(): Int {
    fill(4)
    return buffer.int
  }

  fun ReadUInt16(): Short {
    fill(2)
    return buffer.short
  }

  fun ReadBytes(length: Int): ByteArray {
    val buf = ByteBuffer.wrap(ByteArray(length))
    channel.read(buf)
    return buf.array()
  }

  fun ReadString(length: Int): String {
    val buf = ByteBuffer.wrap(ByteArray(length))
    channel.read(buf)
    buf.position(0)
    return StandardCharsets.US_ASCII.decode(buf).toString()
  }

  private fun fill(length: Int) {
    buffer.clear().limit(length)
    channel.read(buffer)
    buffer.rewind()
  }
}