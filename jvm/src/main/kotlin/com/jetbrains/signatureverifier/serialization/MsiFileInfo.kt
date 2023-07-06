package com.jetbrains.signatureverifier.serialization

import kotlinx.serialization.Serializable

@Serializable
data class MsiFileInfo(
  override val signedDataInfo: SignedDataInfo,
  override val fileMetaInfo: MsiFileMetaInfo
) : FileInfo()