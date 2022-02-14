package com.jetbrains.signatureverifier.crypt

import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*

object Utils {
  fun Throwable.FlatMessages(): String {
    var throwable: Throwable? = this
    val sb = StringBuilder(throwable!!.message)
    while (throwable!!.cause != null) {
      throwable = throwable.cause
      sb.appendLine(throwable!!.message)
    }
    return sb.toString()
  }

  fun Date.ConvertToLocalDateTime(): LocalDateTime {
    return LocalDateTime.ofInstant(
      this.toInstant(), ZoneId.systemDefault()
    )
  }

  fun LocalDateTime.ConvertToDate(): Date {
    return Date
      .from(
        this.atZone(ZoneId.systemDefault())
          .toInstant()
      )
  }

  fun LocalDateTime?.ToString(format: String?): String? {
    return when {
      this == null -> null
      else -> DateTimeFormatter.ofPattern(format).format(this)
    }
  }
}
