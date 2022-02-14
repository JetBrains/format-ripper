package com.jetbrains.signatureverifier

class SignatureData(val SignedData: ByteArray?, val CmsData: ByteArray?) {
  val IsEmpty: Boolean
    get() = CmsData == null
  val HasAttachedSignedData: Boolean
    get() = SignedData != null

  companion object {
    @JvmStatic
    val Empty = SignatureData(null, null)
  }
}
