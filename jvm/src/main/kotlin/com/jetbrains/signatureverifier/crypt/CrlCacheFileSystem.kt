package com.jetbrains.signatureverifier.crypt

import org.bouncycastle.cert.X509CRLHolder
import org.jetbrains.annotations.NotNull
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes
import kotlin.io.path.extension
import kotlin.io.path.pathString
import kotlin.streams.toList

open class CrlCacheFileSystem {
  private val _cacheDir: Path

  constructor() : this("crlscache")

  constructor(@NotNull cacheDir: String) {
    val cacheDirName = cacheDir
    _cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), cacheDirName)
  }

  open fun GetCrls(@NotNull issuerId: String): Collection<X509CRLHolder> {
    val crlFiles = getCrlFiles(issuerId)
    val res = mutableListOf<X509CRLHolder>()
    for (path in crlFiles) {
      val file = path.toFile()
      file.inputStream().use {
        val crl = X509CRLHolder(it)
        res.add(crl)
      }
    }
    return res.toList()
  }

  open fun UpdateCrls(issuerId: String, crlsData: List<ByteArray>) {
    cleanUpCrls(issuerId)
    saveCrls(issuerId, crlsData)
  }

  private fun getCrlFiles(issuerId: String): List<Path> {
    fun filter(path: Path, attrs: BasicFileAttributes): Boolean {
      return path.fileName.toString().startsWith(issuerId) && path.extension == "crl"
    }

    ensureCacheDirectory()
    return Files.find(_cacheDir, 1, ::filter).toList()
  }

  private fun ensureCacheDirectory() {
    if (!Files.exists(_cacheDir))
      Files.createDirectory(_cacheDir)
  }

  private fun cleanUpCrls(issuerId: String) {
    for (crlFile in getCrlFiles(issuerId))
      Files.deleteIfExists(crlFile)
  }

  private fun saveCrls(issuerId: String, crlsData: List<ByteArray>) {
    if (crlsData.count() == 1) {
      val crlFileName = "${issuerId}.crl"
      saveCrl(crlFileName, crlsData[0])
    } else {
      for (i in 0 until crlsData.count()) {
        val crlFileName = "${issuerId}_${i}.crl"
        saveCrl(crlFileName, crlsData[i])
      }
    }
  }

  private fun saveCrl(crlFileName: String, crlData: ByteArray) {
    val crlFilePath = Paths.get(_cacheDir.pathString, crlFileName)
    crlFilePath.toFile().writeBytes(crlData)
  }
}