package com.jetbrains.signatureverifier.bouncycastle.tsp

import org.bouncycastle.asn1.tsp.TSTInfo
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.asn1.tsp.Accuracy
import org.bouncycastle.tsp.GenTimeAccuracy
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.GeneralName
import kotlin.Throws
import java.io.IOException
import java.math.BigInteger
import java.text.ParseException
import java.util.*

class TimeStampTokenInfo internal constructor(var tstInfo: TSTInfo) {
  var genTime: Date? = null

  init {
    try {
      genTime = tstInfo.genTime.date
    } catch (e: ParseException) {
      throw TSPException("unable to parse genTime field")
    }
  }

  val isOrdered: Boolean
    get() = tstInfo.ordering.isTrue
  val accuracy: Accuracy?
    get() = tstInfo.accuracy
  val genTimeAccuracy: GenTimeAccuracy?
    get() = if (accuracy != null) {
      GenTimeAccuracy(accuracy)
    } else null
  val policy: ASN1ObjectIdentifier
    get() = tstInfo.policy
  val serialNumber: BigInteger
    get() = tstInfo.serialNumber.value
  val tsa: GeneralName
    get() = tstInfo.tsa
  val extensions: Extensions
    get() = tstInfo.extensions

  /**
   * @return the nonce value, null if there isn't one.
   */
  val nonce: BigInteger?
    get() = if (tstInfo.nonce != null) {
      tstInfo.nonce.value
    } else null
  val hashAlgorithm: AlgorithmIdentifier
    get() = tstInfo.messageImprint.hashAlgorithm
  val messageImprintAlgOID: ASN1ObjectIdentifier
    get() = tstInfo.messageImprint.hashAlgorithm.algorithm
  val messageImprintDigest: ByteArray
    get() = tstInfo.messageImprint.hashedMessage

  @get:Throws(IOException::class)
  val encoded: ByteArray
    get() = tstInfo.encoded

  @Deprecated("use toASN1Structure")
  fun toTSTInfo(): TSTInfo {
    return tstInfo
  }

  fun toASN1Structure(): TSTInfo {
    return tstInfo
  }
}