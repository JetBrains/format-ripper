package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
sealed interface FileInfo {
  val fileMetaInfo: FileMetaInfo
  val signedDataInfo: SignedDataInfo
  fun modifyFile(stream: SeekableByteChannel) = fileMetaInfo.modifyFile(stream, signedDataInfo.toSignature())
}