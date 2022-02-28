﻿package com.jetbrains.signatureverifier

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

  private val RawPeData: ByteArray by lazy { rawPeData() }

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
    val data = RawPeData
    val hash = MessageDigest.getInstance(algName)

    //hash from start to checksum field
    var offset = 0
    var count = _checkSum.Offset
    hash.update(data, offset, count)

    //jump over checksum and hash to IMAGE_DIRECTORY_ENTRY_SECURITY
    offset = count + _checkSum.Size
    count = _imageDirectoryEntrySecurity.Offset - offset
    hash.update(data, offset, count)

    //jump over IMAGE_DIRECTORY_ENTRY_SECURITY
    offset = _imageDirectoryEntrySecurity.Offset + _imageDirectoryEntrySecurity.Size

    if (_signData.IsEmpty) // PE is not signed
    {
      //hash to EOF
      count = data.count() - offset
      hash.update(data, offset, count)
    } else {
      //PE is signed
      count = _signData.Offset - offset

      //hash to start the signature data
      if ((offset + count) <= data.count())
        hash.update(data, offset, count)

      //jump over the signature data and hash all the rest
      offset = _signData.Offset + _signData.Size
      count = data.count() - offset

      if (count > 0)
        hash.update(data, offset, count)
    }

    return hash.digest()
  }

  private fun rawPeData(): ByteArray {
    return _stream.Rewind().ReadToEnd()
  }
}

