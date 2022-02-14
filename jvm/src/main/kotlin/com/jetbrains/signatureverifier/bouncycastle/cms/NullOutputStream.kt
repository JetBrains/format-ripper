/**
 *
 */
package com.jetbrains.signatureverifier.bouncycastle.cms

import kotlin.Throws
import java.io.IOException
import java.io.OutputStream

internal class NullOutputStream : OutputStream() {
  @Throws(IOException::class)
  override fun write(buf: ByteArray) {
    // do nothing
  }

  @Throws(IOException::class)
  override fun write(buf: ByteArray, off: Int, len: Int) {
    // do nothing
  }

  @Throws(IOException::class)
  override fun write(b: Int) {
    // do nothing
  }
}