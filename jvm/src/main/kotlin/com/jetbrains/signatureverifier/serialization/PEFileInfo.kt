package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable

@Serializable
data class PEFileInfo(
  override val signedDataInfo: SignedDataInfo,
  override val fileMetaInfo: FileMetaInfo
) : FileInfo()