package com.jetbrains.signatureverifier

interface SignableFile {
  fun GetSignatureData(): SignatureData

  /**
   * Computes hash of the file content using the specified algorithm to verify against signature.
   */
  fun ComputeHash(algName: String): ByteArray
}