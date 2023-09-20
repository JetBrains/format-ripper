package com.jetbrains.util

import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.ByteChannel
import java.nio.charset.StandardCharsets

class BinaryReader(private val channel: ByteChannel) {
  /** Reusable buffer */
  private val buffer = ByteBuffer.allocateDirect(8).also { it.order(ByteOrder.nativeOrder()) }

  val BaseStream: ByteChannel
    get() = channel

  fun ReadByte(): Byte {
    fill(1)
    return buffer.get(0)
  }

  fun ReadUInt32(): UInt {
    fill(4)
    return buffer.int.toUInt()
  }

  fun ReadInt64(): Long {
    fill(8)
    return buffer.long
  }

  fun ReadUInt64(): ULong {
    fill(8)
    return buffer.long.toULong()
  }

  fun ReadInt32(): Int {
    fill(4)
    return buffer.int
  }

  fun ReadUInt16(): UShort {
    fill(2)
    return buffer.short.toUShort()
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
    val read = channel.read(buffer)
    if (read <= 0)
      throw EOFException()
    buffer.rewind()
  }
}