package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.NullLogger
import kotlinx.coroutines.future.await
import org.jetbrains.annotations.NotNull
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

open class CrlSource(logger: ILogger? = NullLogger.Instance) {
  private val _logger: ILogger

  init {
    _logger = logger ?: NullLogger.Instance
  }

  open suspend fun GetCrlAsync(@NotNull url: String): ByteArray? {
    try {
      val httpClient = HttpClient.newHttpClient()
      val request = HttpRequest.newBuilder().uri(URI(url)).GET().build()
      val response: HttpResponse<ByteArray> =
        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray()).await()

      if (response.statusCode() != 200) {
        _logger.Warning("CRL downloading fail from $url Status: ${response.statusCode()}")
        return null
      }
      return response.body()
    } catch (ex: Exception) {
      throw Exception("Cannot download CRL from: $url", ex)
    }
  }
}
