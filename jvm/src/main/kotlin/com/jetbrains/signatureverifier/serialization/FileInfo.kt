package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
sealed interface FileInfo {
  val signedDataInfo: SignedDataInfo
  fun modifyFile(stream: SeekableByteChannel)
}