package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformationStore
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

fun deserializeDigestAlgorithms(digestAlgorithms: List<AlgorithmInfo>): ASN1Set =
  listToDLSet(digestAlgorithms.map { it.toPrimitive() })

fun listToDLSequence(list: List<ASN1Encodable?>): DLSequence {
  val vector = ASN1EncodableVector()
  vector.addAll(list.filterNotNull().toTypedArray())
  return DLSequence(vector)
}

fun listToDLSet(list: List<ASN1Encodable>): DLSet {
  val vector = ASN1EncodableVector()
  vector.addAll(list.toTypedArray())
  return DLSet(vector)
}

fun recreateContentInfoFromSignedData(signedData: SignedData): ContentInfo {
  val signedDataBytes = signedData.encoded
  val inputStream = ASN1InputStream(signedDataBytes)
  val asn1Object = inputStream.readObject() as ASN1Primitive

  // Wrap the ASN1Primitive object in a ContentInfo structure
  val contentInfo = ContentInfo(
    ContentInfo.signedData,
    asn1Object
  )

  return contentInfo
}

fun recreateSignerInfosFromSignerInformationStore(signerInfoStore: SignerInformationStore): ASN1Set =
  listToDLSet(signerInfoStore.signers.map { it.toASN1Structure() })

fun compareBytes(
  lhs: ByteArray,
  rhs: ByteArray,
  verbose: Boolean = true
): Boolean {
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

fun byteArrayToHexString(byteArray: ByteArray): String {
  val hexChars = "0123456789ABCDEF"
  val result = StringBuilder(byteArray.size * 2)
  for (byte in byteArray) {
    val value = byte.toInt() and 0xFF
    result.append(hexChars[value ushr 4])
    result.append(hexChars[value and 0x0F])
  }
  return result.toString()
}