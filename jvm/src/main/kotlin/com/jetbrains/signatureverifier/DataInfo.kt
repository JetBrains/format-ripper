package com.jetbrains.signatureverifier

import kotlinx.serialization.Serializable

@Serializable
data class DataInfo(val Offset: Int, val Size: Int) {
  val IsEmpty: Boolean
    get() = Offset == 0 && Size == 0
}

