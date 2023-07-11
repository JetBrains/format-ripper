package com.jetbrains.signatureverifier.serialization

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import kotlinx.serialization.Serializable

@Serializable
class PEFileInfo : FileInfo {
  override val signedDataInfo: SignedDataInfo
  override val fileMetaInfo: FileMetaInfo

  constructor(peFile: PeFile) {
    fileMetaInfo = peFile.getSignatureMetainfo()

    val signatureData = peFile.GetSignatureData()
    val signedMessage = SignedMessage.CreateInstance(signatureData)

    val signedData = signedMessage.SignedData

    signedDataInfo = SignedDataInfo(signedData)
  }
}