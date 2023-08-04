package com.jetbrains.signatureverifier.serialization.fileInfos

import com.jetbrains.signatureverifier.PeFile
import com.jetbrains.signatureverifier.crypt.SignedMessage
import com.jetbrains.signatureverifier.serialization.dataholders.SignedDataInfo
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