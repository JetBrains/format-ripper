package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.PeFile
import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
class PEFileInfo(
  override val signedDataInfo: SignedDataInfo,
  private val peSignatureMetadata: PeFile.Companion.PeSignatureMetadata,
) : FileInfo {
  override fun modifyFile(stream: SeekableByteChannel) {
    PeFile.insertSignature(stream, peSignatureMetadata, signedDataInfo.toSignature())
  }
}