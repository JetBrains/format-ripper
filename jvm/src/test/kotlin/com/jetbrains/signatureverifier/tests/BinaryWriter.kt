package com.jetbrains.signatureverifier.tests

import java.nio.ByteBuffer
import java.nio.channels.ByteChannel

class BinaryWriter(private val channel: ByteChannel) {
  /** Reusable buffer */
  private val buffer = ByteBuffer.allocateDirect(8).also { it.order(java.nio.ByteOrder.LITTLE_ENDIAN) }

  fun Write(value: Int) {
    buffer.clear().limit(Int.SIZE_BYTES)
    buffer.putInt(value)
    buffer.rewind()
    channel.write(buffer)
  }

  fun Write(value: Short) {
    buffer.clear().limit(Short.SIZE_BYTES)
    buffer.putShort(value)
    buffer.rewind()
    channel.write(buffer)
  }

  fun Write(array: ByteArray) {
    val buf = ByteBuffer.wrap(array)
    channel.write(buf)
  }
}
