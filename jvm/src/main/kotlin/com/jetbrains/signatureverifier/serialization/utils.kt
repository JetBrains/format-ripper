package com.jetbrains.signatureverifier.serialization

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.operator.DefaultAlgorithmNameFinder
import java.util.*

fun serializeDigestAlgorithms(algorithmsSet: ASN1Set): List<AlgorithmInfo> =
  algorithmsSet.map {
    val seq = it as DLSequence
    AlgorithmInfo(
      DefaultAlgorithmNameFinder().getAlgorithmName(it.first() as ASN1ObjectIdentifier),
      if (seq.last() is ASN1Null) null else StringInfo.getInstance(seq.last()),
      StringInfo.getInstance(it.first())
    )
  }


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

fun recreateContentInfoFromSignedData(
  signedData: SignedData,
  encoding: String = "BER"
): ContentInfo {
  val signedDataBytes = signedData.getEncoded(encoding)
  val inputStream = ASN1InputStream(signedDataBytes)
  val asn1Object = inputStream.readObject() as ASN1Primitive

  // Wrap the ASN1Primitive object in a ContentInfo structure
  val contentInfo = ContentInfo(
    ContentInfo.signedData,
    asn1Object
  )

  return contentInfo
}

//X500Name.getInstance((value as X500Name).getStyle(), X500Name(value.rdNs)).getEncoded("DER").contentEquals(value.getEncoded("DER"))

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
    println(
      String.format(
        Locale.ENGLISH,
        "Comparing called from %s",
        Thread.currentThread().stackTrace[3].toString()
      )
    )
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

fun hexStringToByteArray(hexString: String): ByteArray {
  val result = ByteArray(hexString.length / 2)
  for (i in 0 until hexString.length step 2) {
    val firstDigit = Character.digit(hexString[i], 16)
    val secondDigit = Character.digit(hexString[i + 1], 16)
    val value = (firstDigit shl 4) + secondDigit
    result[i / 2] = value.toByte()
  }
  return result
}