package com.jetbrains.signatureverifier.serialization

import java.nio.ByteBuffer
import java.util.*

fun compareBytes(
  first: ByteArray,
  second: ByteArray,
  verbose: Boolean = true
): Boolean {
  var lhs = first
  var rhs = second
  if (lhs.size < second.size) {
    lhs = second.also { rhs = lhs }
  }
  if (verbose) {
    println("—————")
  }

  var same = true
  var count = 0
  lhs.forEachIndexed { index, byte ->
    val other = if (index < rhs.size) rhs[index] else 0x0
    if (byte != other) {
      count++
      if (verbose) {
        println(String.format(Locale.ENGLISH, "%d %d %d", index, byte, other))
      }
      same = false
    }
  }
  if (verbose) {
    println(String.format(Locale.ENGLISH, "%d bytes differ", count))
  }
  return same
}


fun ByteArray.toHexString(): String {
  val hexChars = "0123456789ABCDEF"
  val result = StringBuilder(size * 2)
  for (byte in this) {
    val value = byte.toInt() and 0xFF
    result.append(hexChars[value ushr 4])
    result.append(hexChars[value and 0x0F])
  }
  return result.toString()
}

fun String.toByteArray(): ByteArray {
  val result = ByteArray(length / 2)
  for (i in indices step 2) {
    val firstDigit = Character.digit(this[i], 16)
    val secondDigit = Character.digit(this[i + 1], 16)
    val value = (firstDigit shl 4) + secondDigit
    result[i / 2] = value.toByte()
  }
  return result
}

fun Int.toByteArray(isBe: Boolean = false): ByteArray =
  ByteBuffer.allocate(Int.SIZE_BYTES).putInt(this).array().let {
    if (isBe)
      it
    else
      it.reversedArray()
  }

fun UInt.toByteArray(isBe: Boolean = false): ByteArray =
  ByteBuffer.allocate(UInt.SIZE_BYTES).putInt(this.toInt()).array().let {
    if (isBe)
      it
    else
      it.reversedArray()
  }

fun Int.toHexString(): String =
  toByteArray().toHexString()

fun Long.toByteArray(isBe: Boolean = false): ByteArray =
  ByteBuffer.allocate(Long.SIZE_BYTES).putLong(this).array().let {
    if (isBe)
      it
    else
      it.reversedArray()
  }

fun Long.toHexString(): String =
  toByteArray().toHexString()
