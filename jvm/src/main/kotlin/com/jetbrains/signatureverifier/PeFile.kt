package com.jetbrains.signatureverifier

import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.io.IOException
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest

/** Portable Executable file from the specified channel */
class PeFile {
  private val _stream: SeekableByteChannel
  private val _checkSum: DataInfo
  private val _imageDirectoryEntrySecurity: DataInfo
  private val _signData: DataInfo
  private val _dotnetMetadata: DataInfo

  val ImageDirectoryEntrySecurityOffset: Int
    get() = _imageDirectoryEntrySecurity.Offset

  /** PE is .NET assembly */
  val IsDotNet: Boolean
    get() = _dotnetMetadata.IsEmpty.not()

  /** Initializes a new instance of the PeFile */
  constructor(@NotNull stream: SeekableByteChannel) {
    _stream = stream
    _stream.Rewind()

    val reader = BinaryReader(_stream)

    if (reader.ReadUInt16().toInt() != 0x5A4D) //IMAGE_DOS_SIGNATURE
      error("Unknown format")

    stream.Seek(0x3C, SeekOrigin.Begin)
    val ntHeaderOffset = reader.ReadUInt32()
    _checkSum = DataInfo(ntHeaderOffset.toInt() + 0x58, 4)

    stream.Seek(ntHeaderOffset.toLong(), SeekOrigin.Begin)

    if (reader.ReadUInt32().toInt() != 0x00004550) //IMAGE_NT_SIGNATURE
      error("Unknown format")

    stream.Seek(0x12, SeekOrigin.Current) // IMAGE_FILE_HEADER::Characteristics

    val characteristics = reader.ReadUInt16().toInt() and 0x2002

    //IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
    if (characteristics != 0x2002 && characteristics != 0x0002)
      error("Unknown format")

    when (reader.ReadUInt16().toInt()) // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
    {
      // IMAGE_NT_OPTIONAL_HDR32_MAGIC
      0x10b -> stream.Seek(
        0x60L - UShort.SIZE_BYTES,
        SeekOrigin.Current
      ) // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
      // IMAGE_NT_OPTIONAL_HDR64_MAGIC
      0x20b -> stream.Seek(
        0x70L - UShort.SIZE_BYTES,
        SeekOrigin.Current
      ) // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
      else -> error("Unknown format")
    }

    stream.Seek(Long.SIZE_BYTES * 4L, SeekOrigin.Current) // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
    _imageDirectoryEntrySecurity = DataInfo(stream.position().toInt(), 8)
    val securityRva = reader.ReadUInt32().toInt()
    val securitySize = reader.ReadUInt32().toInt()
    _signData = DataInfo(securityRva, securitySize)

    stream.Seek(Long.SIZE_BYTES * 9L, SeekOrigin.Current) // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    val dotnetMetadataRva = reader.ReadUInt32().toInt()
    val dotnetMetadataSize = reader.ReadUInt32().toInt()
    _dotnetMetadata = DataInfo(dotnetMetadataRva, dotnetMetadataSize)
  }

  /** Retrieve the signature data from PE */
  fun GetSignatureData(): SignatureData {
    if (_signData.IsEmpty)
      return SignatureData.Empty

    try {
      val reader = BinaryReader(_stream.Rewind())
      //jump to the sign data
      _stream.Seek(_signData.Offset.toLong(), SeekOrigin.Begin)
      val dwLength = reader.ReadInt32()

      //skip wRevision, wCertificateType
      _stream.Seek(4, SeekOrigin.Current)

      val res = reader.ReadBytes(_signData.Size)

      //need more data
      if (res.count() < dwLength - 8)
        return SignatureData.Empty

      return SignatureData(null, res)
    } catch (ex: IOException) {
      //need more data
      return SignatureData.Empty
    }
  }

  /** Compute hash of PE structure
   * @param algName Name of the hashing algorithm
   * */
  fun ComputeHash(@NotNull algName: String): ByteArray {
    val hash = MessageDigest.getInstance(algName)

    fun hashRange(startOffset: Long, length: Long) {
      if (length <= 0L) return
      val fileSize = _stream.size()
      val safeStart = startOffset.coerceAtLeast(0L).coerceAtMost(fileSize)
      val maxLen = (fileSize - safeStart).coerceAtLeast(0L)
      val safeLen = length.coerceAtMost(maxLen)
      if (safeLen <= 0L) return

      val buffer = ByteArray(1024 * 1024) // 1MB chunks
      var remaining = safeLen
      _stream.Seek(safeStart, SeekOrigin.Begin)
      while (remaining > 0) {
        val toRead = if (remaining < buffer.size) remaining.toInt() else buffer.size
        val bytesRead = _stream.read(java.nio.ByteBuffer.wrap(buffer, 0, toRead))
        if (bytesRead <= 0) break
        hash.update(buffer, 0, bytesRead)
        remaining -= bytesRead
      }
    }

    val fileSize = _stream.size().toInt()

    // 1) Hash from start to checksum field (exclusive)
    var offset = 0
    var count = _checkSum.Offset
    hashRange(offset.toLong(), count.toLong())

    // 2) Skip checksum field, hash up to IMAGE_DIRECTORY_ENTRY_SECURITY (exclusive)
    offset = count + _checkSum.Size
    count = _imageDirectoryEntrySecurity.Offset - offset
    hashRange(offset.toLong(), count.toLong())

    // 3) Skip IMAGE_DIRECTORY_ENTRY_SECURITY itself (8 bytes)
    offset = _imageDirectoryEntrySecurity.Offset + _imageDirectoryEntrySecurity.Size

    if (_signData.IsEmpty) {
      // 4a) Not signed: hash to EOF
      count = fileSize - offset
      hashRange(offset.toLong(), count.toLong())
    } else {
      // 4b) Signed: hash up to the start of signature data
      count = _signData.Offset - offset
      if (offset + count <= fileSize) {
        hashRange(offset.toLong(), count.toLong())
      }

      // 5) Jump over signature data and hash the rest to EOF
      offset = _signData.Offset + _signData.Size
      count = fileSize - offset
      if (count > 0) {
        hashRange(offset.toLong(), count.toLong())
      }
    }

    return hash.digest()
  }
}

