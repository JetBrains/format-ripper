package com.jetbrains.signatureverifier

import org.jetbrains.annotations.NotNull

interface ILogger {
  fun Info(@NotNull str: String)
  fun Warning(@NotNull str: String)
  fun Error(@NotNull str: String)
  fun Trace(@NotNull str: String)
}
