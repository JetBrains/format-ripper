package com.jetbrains.signatureverifier.cf

import com.jetbrains.signatureverifier.SignatureData
import org.jetbrains.annotations.NotNull
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest

/**
 * MS Windows Installer compound file
 */
open class MsiFile {
  private val _cf: CompoundFile

  //\u0005DigitalSignature
  private val _digitalSignatureEntryName = arrayOf<Byte>(
    0x5, 0x0, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53,
    0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00
  ).toByteArray()

  //\u0005MsiDigitalSignatureEx
  private val _msiDigitalSignatureExEntryName = arrayOf<Byte>(
    0x5, 0x0, 0x4D, 0x00, 0x73, 0x00, 0x69, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61,
    0x00, 0x6C, 0x00, 0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00,
    0x65, 0x00, 0x45, 0x00, 0x78, 0x00
  ).toByteArray()

  /**
   * Initializes a new instance of the MsiFile
   *
   * @param stream  An input stream
   * @exception PlatformNotSupportedException  Indicates the byte order ("endianness")
   *      in which data is stored in this computer architecture is not Little Endian.
   * @exception InvalidDataException  If the input stream contains a compound file with wrong structure
   */
  constructor(@NotNull stream: SeekableByteChannel) {
    _cf = CompoundFile(stream)
  }

  /**
   * Retrieve the signature data from MSI
   */
  fun GetSignatureData(): SignatureData {
    val data = _cf.GetStreamData(_digitalSignatureEntryName)

    if (data == null)
      return SignatureData.Empty

    return SignatureData(null, data)
  }

  /**
   * Compute hash of MSI structure
   *
   * @param algName  Name of the hashing algorithm
   * @param skipMsiDigitalSignatureExEntry  Skip \u0005MsiDigitalSignatureEx entry data when hashing
   */
  fun ComputeHash(@NotNull algName: String, skipMsiDigitalSignatureExEntry: Boolean): ByteArray {
    val entries = _cf.GetStreamDirectoryEntries()
      .sortedWith { e1: DirectoryEntry, e2: DirectoryEntry -> compareDirectoryEntries(e1, e2) }

    val hash = MessageDigest.getInstance(algName)

    for (entry in entries) {
      if (entry.Name.contentEquals(_digitalSignatureEntryName))
        continue

      if (skipMsiDigitalSignatureExEntry && entry.Name.contentEquals(_msiDigitalSignatureExEntryName))
        continue

      val data = _cf.GetStreamData(entry)
      hash.update(data)
    }

    val rootClsid = _cf.GetRootDirectoryClsid()

    if (rootClsid != null)
      hash.update(rootClsid)

    return hash.digest()
  }

  private fun compareDirectoryEntries(e1: DirectoryEntry, e2: DirectoryEntry): Int {
    val a = e1.Name
    val b = e2.Name
    val size = Math.min(a.count(), b.count())

    for (i in 0 until size)
      if (a[i] != b[i])
        return (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)

    return a.count() - b.count()
  }
}

