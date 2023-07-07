package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
data class DmgFileInfo(
  override val fileMetaInfo: DmgFileMetaInfo,
  override val signedDataInfo: SignedDataInfo
) : FileInfo(){
  override fun modifyFile(stream: SeekableByteChannel) {
    fileMetaInfo.modifyFile(stream, signedDataInfo.toSignature("BER"))
  }
}