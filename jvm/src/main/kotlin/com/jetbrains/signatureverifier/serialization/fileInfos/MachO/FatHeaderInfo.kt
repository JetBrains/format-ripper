package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.serialization.toByteArray
import kotlinx.serialization.Serializable

@Serializable
data class FatHeaderInfo(
  var magic: UInt = 0u,
  var isBe: Boolean = false,
  var fatArchSize: UInt = 0u,
  val fatArchInfos: MutableList<FatArchInfo> = mutableListOf()
) {
  fun toByteArray() =
    magic.toByteArray() +
      fatArchSize.toByteArray(isBe) +
      fatArchInfos.fold(byteArrayOf()) { acc, it -> acc + it.toByteArray(isBe) }
}
