package com.jetbrains.signatureverifier.tests

import com.jetbrains.signatureverifier.ILogger
import org.jetbrains.annotations.NotNull

class ConsoleLogger : ILogger {
  companion object {
    @JvmStatic
    val Instance = ConsoleLogger()
  }

  override fun Info(@NotNull str: String) = println("INFO: $str")
  override fun Warning(@NotNull str: String) = println("WARNING: $str")
  override fun Error(@NotNull str: String) = println("ERROR: $str")
  override fun Trace(@NotNull str: String) = println("TRACE: $str")
}