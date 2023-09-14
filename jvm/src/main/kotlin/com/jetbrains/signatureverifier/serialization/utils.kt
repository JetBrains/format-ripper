package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.serialization.dataholders.EncodableInfo
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import java.nio.ByteBuffer
import java.util.*

fun List<EncodableInfo>.toPrimitiveList(): List<ASN1Encodable?> = this.map { it.toPrimitive() }

fun List<EncodableInfo>.toPrimitiveDLSequence(): DLSequence = this.toPrimitiveList().toDLSequence()
fun List<EncodableInfo>.toPrimitiveDLSet(): DLSet = this.toPrimitiveList().toDLSet()

fun List<ASN1Encodable?>.toDLSequence(): DLSequence {
  val vector = ASN1EncodableVector()
  vector.addAll(this.filterNotNull().toTypedArray())
  return DLSequence(vector)
}

fun List<ASN1Encodable?>.toDLSet(): DLSet {
  val vector = ASN1EncodableVector()
  vector.addAll(this.filterNotNull().toTypedArray())
  return DLSet(vector)
}

fun SignedData.toContentInfo(encoding: String = "BER"): ContentInfo {
  val signedDataBytes = this.getEncoded(encoding)
  val inputStream = ASN1InputStream(signedDataBytes)
  val asn1Object = inputStream.readObject() as ASN1Primitive

  return ContentInfo(
    ContentInfo.signedData,
    asn1Object
  )
}


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

fun mergeSegments(segments: MutableList<Pair<Int, Int>>): MutableList<Pair<Int, Int>> {
  if (segments.size <= 1) return segments

  // Sort the segments by first element of pair.
  segments.sortBy { it.first }

  val result = mutableListOf<Pair<Int, Int>>()
  result.add(segments[0])

  for (i in 1 until segments.size) {
    // If current segment's start is less than or equal to previous segment's end, then update previous segment's end
    if (result.last().second >= segments[i].first) {
      val lastElement = result.removeLast()
      result.add(Pair(lastElement.first, lastElement.second.coerceAtLeast(segments[i].second)))
    } else {
      result.add(segments[i]) // Otherwise, add current segment as separate.
    }
  }
  return result
}

fun findGaps(start: Int, end: Int, segments: List<Pair<Int, Int>>): List<Pair<Int, Int>> {
  val gaps = mutableListOf<Pair<Int, Int>>()
  var currStart = start

  for ((segStart, segEnd) in segments) {
    if (segStart > currStart) {
      gaps.add(Pair(currStart - 1, segStart))
    }
    currStart = (segEnd).coerceAtLeast(currStart)
  }

  if (currStart <= end) {
    gaps.add(Pair(currStart, end))
  }

  return gaps
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
