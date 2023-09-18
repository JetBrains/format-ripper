package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.macho.MachoFile
import kotlinx.serialization.Serializable
import java.nio.channels.SeekableByteChannel

@Serializable
class MachoFileInfo : FileInfo {
  override val fileMetaInfo: FileMetaInfo
  override val signedDataInfo: SignedDataInfo

  constructor(machoFile: MachoFile) {
    val signatureData = machoFile.GetSignatureData()
    val signedMessage = SignedMessage.CreateInstance(signatureData)
    val signedData = signedMessage.SignedData

    signedDataInfo = SignedDataInfo(signedData)
    fileMetaInfo = machoFile.metaInfo
  }

  override fun modifyFile(stream: SeekableByteChannel) {
    fileMetaInfo.modifyFile(stream, signedDataInfo.toSignature("BER"))
  }
}