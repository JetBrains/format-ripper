package com.jetbrains.signatureverifier

import org.jetbrains.annotations.NotNull

class NullLogger : ILogger {
  companion object {
    @JvmStatic
    val Instance = NullLogger()
  }

  override fun Info(@NotNull str: String) {
  }

  override fun Warning(@NotNull str: String) {
  }

  override fun Error(@NotNull str: String) {
  }

  override fun Trace(@NotNull str: String) {
  }
}
