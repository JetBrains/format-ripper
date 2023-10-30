package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import java.util.*

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