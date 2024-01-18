package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.cms.CMSException
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.tsp.TSPValidationException
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

  //Ignores exceptions of the specified classes when they have certain error messages
  private val ignoredExceptions = mapOf(
    Pair(
      CMSException::class.java,
      setOf("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute")
    ),
    Pair(
      TSPValidationException::class.java,
      setOf("Certificate must have an ExtendedKeyUsage extension marked as critical.")
    )
  )

  fun isExceptionIgnored(exception: Throwable): Boolean {
    val messages = ignoredExceptions[exception::class.java]
    return messages != null && messages.contains(exception.FlatMessages())
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
