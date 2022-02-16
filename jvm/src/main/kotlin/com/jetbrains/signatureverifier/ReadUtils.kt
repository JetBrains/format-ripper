﻿package com.jetbrains.signatureverifier

import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel

fun SeekableByteChannel.Rewind(): SeekableByteChannel {
  this.position(0)
  return this
}

fun SeekableByteChannel.Seek(position: Long, origin: SeekOrigin) {
  when (origin) {
    SeekOrigin.Begin -> this.position(position)
    SeekOrigin.Current -> this.position(this.position() + position)
    SeekOrigin.End -> this.position(this.size() - 1)
  }
}

fun SeekableByteChannel.ReadAll(): ByteArray {
  this.Rewind()
  val buf = ByteBuffer.wrap(ByteArray(this.size().toInt()))
  this.read(buf)
  return buf.array()
}

fun SeekableByteChannel.ReadToEnd(): ByteArray {
  val pos = this.position()
  val size = this.size()
  if (pos + 1 == size)
    return ByteArray(0)
  val buf = ByteBuffer.wrap(ByteArray((size - pos).toInt()))
  this.read(buf)
  return buf.array()
}

fun BinaryReader.ReadUInt32Le(isBe: Boolean): UInt {
  val value = this.ReadUInt32()
  return if (isBe) SwapBytes(value) else value
}

fun BinaryReader.ReadUInt64Le(isBe: Boolean): ULong {
  val value = this.ReadUInt64()
  return if (isBe) SwapBytes(value) else value
}

private fun SwapBytes(v: UShort): UShort = (((v.toInt() and 0xFF) shl 8) or ((v.toInt() ushr 8) and 0xFF)).toUShort()

private fun SwapBytes(v: UInt): UInt =
  (SwapBytes(v.toUShort()).toUInt() shl 16) or (SwapBytes((v shr 16).toUShort()).toUInt())

private fun SwapBytes(v: ULong): ULong =
  (SwapBytes(v.toUInt()) shl 32).toULong() or (SwapBytes(v.toUInt()) shr 32).toULong()
