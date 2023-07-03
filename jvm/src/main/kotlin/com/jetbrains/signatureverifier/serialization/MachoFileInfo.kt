package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
class MachoFileInfo(override val fileMetaInfo: FileMetaInfo, override val signedDataInfo: SignedDataInfo) : FileInfo {
  override fun modifyFile(stream: SeekableByteChannel) {
    fileMetaInfo.modifyFile(stream, signedDataInfo.toSignature("BER"))
  }
}