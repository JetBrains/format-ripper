package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

@Serializable
data class CodeSignatureInfo(
  var magic: UInt = 0u,
  var length: UInt = 0u,
  var superBlobStart: Long = 0L,
  var superBlobCount: Int = 0,
  var blobs: MutableList<Blob> = mutableListOf()
) {
  fun toByteArray() =
    magic.toByteArray(true) + length.toByteArray(true) + blobs.count().toByteArray(true) +
      blobs.fold(byteArrayOf()) { acc, it -> acc + it.type.toByteArray(true) + it.offset.toByteArray(true) }
}