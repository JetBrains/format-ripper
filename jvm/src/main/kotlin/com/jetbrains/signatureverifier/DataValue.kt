package com.jetbrains.signatureverifier

import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import kotlinx.serialization.Serializable

@Serializable
data class DataValue(
  val dataInfo: DataInfo = DataInfo(0, 0),
  @Serializable(ByteArraySerializer::class)
  val value: ByteArray = emptyList<Byte>().toByteArray()
)