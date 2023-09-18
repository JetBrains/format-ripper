package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData
import kotlinx.serialization.Serializable

@Serializable
data class SignedDataInfo(
  private val _dataDer: ByteArray,
  private val _dataBer: ByteArray
) {
  constructor(signedData: CMSSignedData) :
    this(
      signedData.getEncoded("DER"),
      signedData.getEncoded("BER")
    )

  fun toSignature(encoding: String = "DER"): ByteArray = when (encoding) {
    "DER" -> _dataDer
    "BER" -> _dataBer
    else -> throw Exception("Unknown encoding $encoding")
  }
}