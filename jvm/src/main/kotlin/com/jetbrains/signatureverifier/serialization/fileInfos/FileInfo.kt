package com.jetbrains.signatureverifier.serialization.fileInfos

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
sealed class FileInfo {
  abstract val fileMetaInfo: FileMetaInfo
  abstract val signedDataInfo: SignedDataInfo
  open fun modifyFile(stream: SeekableByteChannel) = fileMetaInfo.modifyFile(stream, signedDataInfo.toSignature())
}