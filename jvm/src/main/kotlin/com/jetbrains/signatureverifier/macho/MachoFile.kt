package com.jetbrains.signatureverifier.macho

import com.jetbrains.signatureverifier.*
import com.jetbrains.util.*
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import org.jetbrains.annotations.NotNull
import java.io.IOException
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest
import java.text.ParseException

open class MachoFile {
  private val _stream: SeekableByteChannel
  var Magic: Long = 0
  val isLe32: Boolean
    get() = Magic == MachoConsts.MH_MAGIC
  val isLe64: Boolean
    get() = Magic == MachoConsts.MH_MAGIC_64
  val isBe32: Boolean
    get() = Magic == MachoConsts.MH_CIGAM
  val isBe64: Boolean
    get() = Magic == MachoConsts.MH_CIGAM_64
  val is32: Boolean
    get() = isLe32 || isBe32
  val isBe: Boolean
    get() = isBe32 || isBe64
  private val ncmdsOffset = DataInfo(16, 8)
  private var ncmds: Long = 0
  private var sizeofcmds: Long = 0
  private var firstLoadCommandPosition: Long = 0

  /**
   * Initializes a new instance of the MachoFile
   *
   * @param stream  An input stream
   * @exception ParseException  Indicates the byte order ("endianness")
   *      in which data is stored in this computer architecture is not Little Endian.
   * @exception InvalidDataException  If the input stream not contain MachO
   */
  constructor(@NotNull stream: SeekableByteChannel) {
    _stream = stream
    setMagic()
  }

  /**
   * Initializes a new instance of the MachoFile
   *
   * @param data  A raw data
   * @exception ParseException  Indicates the byte order ("endianness")
   *      in which data is stored in this computer architecture is not Little Endian.
   * @exception InvalidDataException  If the input data not contain MachO
   */
  constructor(@NotNull data: ByteArray) {
    _stream = SeekableInMemoryByteChannel(data)
    setMagic()
  }

  private fun setMagic() {
    val reader = BinaryReader(_stream.Rewind())
    Magic = reader.ReadUInt32().toLong() // mach_header::magic / mach_header64::magic

    if (!MachoUtils.IsMacho(Magic))
      throw InvalidDataException("Unknown format")

    _stream.Seek(ncmdsOffset.Offset.toLong(), SeekOrigin.Begin)
    ncmds = reader.ReadUInt32Le(isBe).toLong() // mach_header::ncmds / mach_header_64::ncmds
    sizeofcmds = reader.ReadUInt32Le(isBe).toLong() // mach_header::sizeofcmds / mach_header_64::sizeofcmds
    firstLoadCommandPosition = _stream.position() + (if (is32) 4 else 8)// load_command[0]
  }

  fun ComputeHash(algName: String): ByteArray {
    val (excludeRanges, hasLcCodeSignature) = getHashExcludeRanges()
    val hash = MessageDigest.getInstance(algName)
    if (excludeRanges.any()) {
      val reader = BinaryReader(_stream.Rewind())
      for (dataInfo in excludeRanges) {
        val size = dataInfo.Offset - _stream.position()
        if (size > 0) {
          hash.update(reader.ReadBytes(size.toInt()))
          _stream.Seek(dataInfo.Size.toLong(), SeekOrigin.Current)
        }
      }
      hash.update(_stream.ReadToEnd())
      //append the zero-inset to the end of data. codesign does it as well
      if (!hasLcCodeSignature) {
        val filesize = _stream.position()
        var zeroInsetSize = filesize % 16
        if (zeroInsetSize > 0) {
          zeroInsetSize = 16 - zeroInsetSize
          hash.update(ByteArray(zeroInsetSize.toInt()))
        }
      }
    } else {
      hash.update(_stream.ReadAll())
    }
    return hash.digest()
  }

  private fun getHashExcludeRanges(): Pair<MutableList<DataInfo>, Boolean> {
    val excludeRanges = mutableListOf(ncmdsOffset)
    val reader = BinaryReader(_stream)
    _stream.Seek(firstLoadCommandPosition, SeekOrigin.Begin)// load_command[0]

    var hasLcCodeSignature = false
    var _ncmds = ncmds
    while (_ncmds-- > 0) {
      val cmpPosition = _stream.position()
      val cmd = reader.ReadUInt32Le(isBe32 || isBe64)
      // load_command::cmd
      val cmdsize = reader.ReadUInt32Le(isBe32 || isBe64)

      // load_command::cmdsize
      if (cmd.toInt() == MachoConsts.LC_SEGMENT || cmd.toInt() == MachoConsts.LC_SEGMENT_64) {
        val segname = reader.ReadString(10)
        if (segname == "__LINKEDIT") {
          _stream.Seek(6, SeekOrigin.Current)//skip to end of segname which is 16 byte
          _stream.Seek(if (is32) 4 else 8, SeekOrigin.Current)//skip vmaddr

          val vmsizeOffset = DataInfo(_stream.position().toInt(), if (is32) 4 else 8)
          excludeRanges.add(vmsizeOffset)

          _stream.Seek((if (is32) 4 else 8).toLong() * 2, SeekOrigin.Current)//skip vmsize and fileoff

          val filesizeOffset = DataInfo(_stream.position().toInt(), if (is32) 4 else 8)
          excludeRanges.add(filesizeOffset)
        }
      } else if (cmd.toInt() == MachoConsts.LC_CODE_SIGNATURE) {
        val lcCodeSignatureOffset = DataInfo(cmpPosition.toInt(), cmdsize.toInt())
        excludeRanges.add(lcCodeSignatureOffset)
        val lcCodeSignatureDataOffset = DataInfo(
          reader.ReadUInt32Le(isBe).toInt()   // load_command::dataoffn,
          , reader.ReadUInt32Le(isBe).toInt() // load_command::datasize
        )

        excludeRanges.add(lcCodeSignatureDataOffset)
        hasLcCodeSignature = true
      }
      _stream.Seek((cmdsize - (_stream.position().toUInt() - cmpPosition.toUInt())).toLong(), SeekOrigin.Current)
    }
    if (!hasLcCodeSignature) {
      //exclude the LC_CODE_SIGNATURE zero placeholder from hashing
      excludeRanges.add(DataInfo((firstLoadCommandPosition + sizeofcmds).toInt(), 16))
    }
    return Pair(excludeRanges, hasLcCodeSignature)
  }

  /**
   * Retrieve the signature data from MachO
   *
   * @exception InvalidDataException  Indicates the data in the input stream does not correspond to MachO format or the signature data is malformed
   */
  fun GetSignatureData(): SignatureData {
    try {
      return getMachoSignatureData()
    } catch (ex: IOException) {
      throw InvalidDataException("Invalid format")
    }
  }

  private fun getMachoSignatureData(): SignatureData {
    // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
    var signedData: ByteArray? = null
    var cmsData: ByteArray? = null
    val reader = BinaryReader(_stream)
    _stream.Seek(firstLoadCommandPosition, SeekOrigin.Begin)// load_command[0]

    var _ncmds = ncmds
    while (_ncmds-- > 0) {
      val cmd = reader.ReadUInt32Le(isBe32 || isBe64)
      // load_command::cmd
      val cmdsize = reader.ReadUInt32Le(isBe32 || isBe64)
      // load_command::cmdsize
      if (cmd.toInt() == MachoConsts.LC_CODE_SIGNATURE) {
        val dataoff = reader.ReadUInt32Le(isBe32 || isBe64)
        // load_command::dataoff
        _stream.Seek(dataoff.toLong(), SeekOrigin.Begin)
        val CS_SuperBlob_start = _stream.position()
        _stream.Seek(8, SeekOrigin.Current)
        var CS_SuperBlob_count = reader.ReadUInt32Le(true).toInt()
        while (CS_SuperBlob_count-- > 0) {
          val CS_BlobIndex_type = reader.ReadUInt32Le(true)
          val CS_BlobIndex_offset = reader.ReadUInt32Le(true)
          val position = _stream.position()
          if (CS_BlobIndex_type.toInt() == MachoConsts.CSSLOT_CODEDIRECTORY) {
            _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin)
            _stream.Seek(CS_BlobIndex_offset.toLong(), SeekOrigin.Current)
            signedData = MachoUtils.ReadCodeDirectoryBlob(reader)
            _stream.Seek(position, SeekOrigin.Begin)
          } else if (CS_BlobIndex_type.toInt() == MachoConsts.CSSLOT_CMS_SIGNATURE) {
            _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin)
            _stream.Seek(CS_BlobIndex_offset.toLong(), SeekOrigin.Current)
            cmsData = MachoUtils.ReadBlob(reader)
            _stream.Seek(position, SeekOrigin.Begin)
          }
        }
      }
      _stream.Seek((cmdsize.toLong() - 8), SeekOrigin.Current)
    }
    return SignatureData(signedData, cmsData)
  }
}
