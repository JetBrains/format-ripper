package com.jetbrains.signatureverifier

import kotlinx.serialization.Serializable

@Serializable
data class DataValue(val dataInfo: DataInfo = DataInfo(0, 0), val value: String = "")