package com.jetbrains.signatureverifier.crypt

import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.NullLogger
import com.jetbrains.signatureverifier.crypt.BcExt.FormatId
import com.jetbrains.signatureverifier.crypt.BcExt.GetAuthorityKeyIdentifier
import com.jetbrains.signatureverifier.crypt.BcExt.GetCrlDistributionUrls
import com.jetbrains.signatureverifier.crypt.BcExt.Thumbprint
import com.jetbrains.signatureverifier.crypt.Utils.ConvertToDate
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.jetbrains.annotations.NotNull
import java.time.LocalDateTime

open class CrlProvider {
  private val _crlSource: CrlSource
  private val _crlCash: CrlCacheFileSystem
  private val _logger: ILogger

  constructor(logger: ILogger?)
    : this(CrlSource(logger), CrlCacheFileSystem(), logger)

  constructor(@NotNull crlSource: CrlSource, @NotNull crlCash: CrlCacheFileSystem, logger: ILogger?) {
    _crlSource = crlSource
    _crlCash = crlCash
    _logger = logger ?: NullLogger.Instance
  }

  suspend fun GetCrlsAsync(cert: X509CertificateHolder): Collection<X509CRLHolder> {
    val crlId = cert.GetAuthorityKeyIdentifier() ?: cert.Thumbprint()
    val res = _crlCash.GetCrls(crlId)

    if (res.count() != 0 && !crlsIsOutDate(res))
      return res

    val urls = cert.GetCrlDistributionUrls()
    if (urls.count() < 1)
      _logger.Warning("No CRL distribution urls in certificate ${cert.FormatId()}")

    val crlsData = downloadCrlsAsync(urls)
    //We have to filter out CRLs with an empty NextUpdate field
    //See https://github.com/bcgit/bc-csharp/issues/315
    val crls = crlsData.map { s ->
      object {
        val Crl = X509CRLHolder(s)
        val Data = s
      }
    }.filter { w -> w.Crl.nextUpdate != null }
      .toList()
    _crlCash.UpdateCrls(crlId, crls.map { s -> s.Data }.toList())
    return crls.map { s -> s.Crl }.toList()
  }

  private suspend fun downloadCrlsAsync(urls: Collection<String>): Collection<ByteArray> {
    val res = mutableListOf<ByteArray>()
    for (url in urls) {
      val crlData = _crlSource.GetCrlAsync(url)
      if (crlData != null)
        res.add(crlData)
    }
    return res
  }

  private fun crlsIsOutDate(crls: Collection<X509CRLHolder>): Boolean {
    val now = LocalDateTime.now().ConvertToDate()
    return crls.any { a -> a.nextUpdate!!.before(now) }
  }
}
