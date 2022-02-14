package com.jetbrains.signatureverifier

data class DataInfo(val Offset: Int, val Size: Int) {
  val IsEmpty: Boolean
    get() = Offset == 0 && Size == 0
}

