package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
sealed interface FileMetaInfo {
  fun modifyFile(stream: SeekableByteChannel, signature: ByteArray)
}