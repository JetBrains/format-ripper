package com.jetbrains.signatureverifier

import java.io.InputStream

object Resources {
  fun GetDefaultRoots(): InputStream = getResourceStream("DefaultRoots.p7b")

  private fun getResourceStream(name: String): InputStream {
    return Resources.javaClass.classLoader.getResourceAsStream(name)!!
  }
}