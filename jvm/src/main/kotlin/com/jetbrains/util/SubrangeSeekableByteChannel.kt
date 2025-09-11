package com.jetbrains.util

import java.nio.ByteBuffer
import java.nio.channels.NonWritableChannelException
import java.nio.channels.SeekableByteChannel

/**
 * A read-only SeekableByteChannel that exposes a subrange [startOffset, startOffset + length)
 * of an underlying base channel. The channel maintains its own independent position within
 * the subrange and does not close the base channel when closed.
 */
class SubrangeSeekableByteChannel(
  private val base: SeekableByteChannel,
  private val startOffset: Long,
  private val length: Long
) : SeekableByteChannel {
  private var pos: Long = 0

  init {
    require(startOffset >= 0) { "startOffset must be >= 0" }
    require(length >= 0) { "length must be >= 0" }
  }

  override fun isOpen(): Boolean = base.isOpen

  // Do not close the base channel; subrange view is lightweight.
  override fun close() { /* no-op */ }

  override fun read(dst: ByteBuffer): Int {
    if (pos >= length) return -1
    if (!dst.hasRemaining()) return 0

    val allowed = Math.min(length - pos, dst.remaining().toLong()).toInt()

    // Save original limit and restrict to allowed bytes
    val originalLimit = dst.limit()
    val limitedLimit = dst.position() + allowed
    if (limitedLimit < originalLimit) {
      dst.limit(limitedLimit)
    }

    // Position base to absolute offset and read
    base.position(startOffset + pos)
    val read = try {
      base.read(dst)
    } finally {
      // Restore original limit
      dst.limit(originalLimit)
    }

    if (read > 0) pos += read.toLong()
    return if (read == 0 && allowed == 0) -1 else read
  }

  override fun write(src: ByteBuffer): Int {
    throw NonWritableChannelException()
  }

  override fun position(): Long = pos

  override fun position(newPosition: Long): SeekableByteChannel {
    require(newPosition >= 0) { "position must be >= 0" }
    require(newPosition <= length) { "position must be <= length" }
    pos = newPosition
    return this
  }

  override fun size(): Long = length

  override fun truncate(size: Long): SeekableByteChannel {
    throw NonWritableChannelException()
  }
}
