package com.jetbrains.signatureverifier.macho

import com.jetbrains.signatureverifier.DataInfo
import com.jetbrains.signatureverifier.InvalidDataException
import com.jetbrains.signatureverifier.SignatureData
import com.jetbrains.signatureverifier.serialization.fileInfos.*
import com.jetbrains.util.*
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import org.jetbrains.annotations.NotNull
import java.io.IOException
import java.nio.ByteOrder
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
  val metaInfo = MachoFileMetaInfo()

  /**
   * Initializes a new instance of the MachoFile
   *
   * @param stream  An input stream
   * @exception ParseException  Indicates the byte order ("endianness")
   *      in which data is stored in this computer architecture is not Little Endian.
   * @exception InvalidDataException  If the input stream not contain MachO
   */
  constructor(@NotNull stream: SeekableByteChannel) {
    if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
      throw ParseException("Only Little endian is expected", 0)
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
  constructor(@NotNull data: ByteArray, fileSize: Long, offset: Long = 0) {
    if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
      throw ParseException("Only Little endian is expected", 0)
    _stream = SeekableInMemoryByteChannel(data)
    metaInfo.machoOffset = offset
    metaInfo.fileSize = fileSize
    setMagic()
  }

  private fun setMagic() {
    val reader = BinaryReader(_stream.Rewind())
    Magic = reader.ReadUInt32().toLong() // mach_header::magic / mach_header64::magic

    metaInfo.isBe = isBe
    if (!MachoUtils.IsMacho(Magic))
      throw InvalidDataException("Unknown format")


//    _stream.Seek(ncmdsOffset.Offset.toLong(), SeekOrigin.Begin)
    val cpuType = reader.ReadUInt32Le(isBe)
    val cpuSubType = reader.ReadUInt32Le(isBe)
    val fileType = reader.ReadUInt32Le(isBe)

    ncmds = reader.ReadUInt32Le(isBe).toLong() // mach_header::ncmds / mach_header_64::ncmds
    sizeofcmds = reader.ReadUInt32Le(isBe).toLong() // mach_header::sizeofcmds / mach_header_64::sizeofcmds
    firstLoadCommandPosition = _stream.position() + (if (is32) 4 else 8)// load_command[0]

    val flags = reader.ReadUInt32Le(isBe)
    val reserved = reader.ReadUInt32Le(isBe)

    metaInfo.headerMetaInfo = MachoHeaderMetaInfo(
      Magic.toUInt(),
      cpuType,
      cpuSubType,
      fileType,
      ncmds.toUInt(),
      sizeofcmds.toUInt(),
      flags,
      reserved
    )
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
    var requirementsData: ByteArray? = null

    val reader = BinaryReader(_stream)
    _stream.Seek(firstLoadCommandPosition, SeekOrigin.Begin)// load_command[0]

    var _ncmds = ncmds
    while (_ncmds-- > 0) {
      val cmdStreamPosition = _stream.position()
      val cmd = reader.ReadUInt32Le(isBe32 || isBe64)
      // load_command::cmd
      val cmdsize = reader.ReadUInt32Le(isBe32 || isBe64)
      // load_command::cmdsize
      if (cmd.toInt() == MachoConsts.LC_SEGMENT_64 || cmd.toInt() == MachoConsts.LC_SEGMENT) {
        val name = reader.ReadBytes(16)
        if (name.contentEquals(MachoConsts.LINKEDIT_SEGMENT_NAME)) {
          metaInfo.loadCommands.add(
            LoadCommandLinkeditInfo(
              cmdStreamPosition,
              cmd,
              cmdsize,
              name,
              reader.ReadUInt64Le(false),
              reader.ReadUInt64Le(false),
              reader.ReadUInt64Le(false),
              reader.ReadUInt64Le(false),
              reader.ReadUInt32Le(true),
              reader.ReadUInt32Le(true),
              reader.ReadUInt32Le(true),
              reader.ReadUInt32Le(true),
            )
          )
        }
      } else if (cmd.toInt() == MachoConsts.LC_CODE_SIGNATURE) {
        val dataOff = reader.ReadUInt32Le(isBe32 || isBe64)
        val dataSize = reader.ReadUInt32Le(isBe32 || isBe64)
        metaInfo.loadCommands.add(
          LoadCommandSignatureInfo(
            cmdStreamPosition,
            cmd,
            cmdsize,
            dataOff,
            dataSize
          )
        )

        // load_command::dataoff
        _stream.Seek(dataOff.toLong(), SeekOrigin.Begin)
        val CS_SuperBlob_start = _stream.position()

        metaInfo.codeSignatureInfo.superBlobStart = CS_SuperBlob_start

//        _stream.Seek(8, SeekOrigin.Current)
        metaInfo.codeSignatureInfo.magic = reader.ReadUInt32Le(true)
        metaInfo.codeSignatureInfo.length = reader.ReadUInt32Le(true)

        var CS_SuperBlob_count = reader.ReadUInt32Le(true).toInt()
        metaInfo.codeSignatureInfo.superBlobCount = CS_SuperBlob_count

        while (CS_SuperBlob_count-- > 0) {
          val CS_BlobIndex_type = reader.ReadUInt32Le(true)
          val CS_BlobIndex_offset = reader.ReadUInt32Le(true)
          val position = _stream.position()
          when (CS_BlobIndex_type.toLong()) {
            MachoConsts.CSSLOT_CODEDIRECTORY -> {
              _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin)
              _stream.Seek(CS_BlobIndex_offset.toLong(), SeekOrigin.Current)
              val (blobMagic, data) = MachoUtils.ReadCodeDirectoryBlob(reader)
              signedData = data
              _stream.Seek(position, SeekOrigin.Begin)

              metaInfo.codeSignatureInfo.blobs.add(
                Blob(
                  CS_BlobIndex_type,
                  CS_BlobIndex_offset,
                  CSMAGIC.CODEDIRECTORY,
                  blobMagic,
                  signedData
                )
              )
            }

            else -> {
              val magicEnum = CSMAGIC.getInstance(CS_BlobIndex_type)

              _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin)
              _stream.Seek(CS_BlobIndex_offset.toLong(), SeekOrigin.Current)
              val (blobMagic, data) = MachoUtils.ReadBlob(reader)
              _stream.Seek(position, SeekOrigin.Begin)

              metaInfo.codeSignatureInfo.blobs.add(
                Blob(
                  CS_BlobIndex_type,
                  CS_BlobIndex_offset,
                  magicEnum,
                  blobMagic,
                  if (magicEnum == CSMAGIC.CMS_SIGNATURE) {
                    cmsData = data
                    byteArrayOf()
                  } else data
                )
              )
            }
          }
        }
      }
      _stream.Jump(cmdStreamPosition + cmdsize.toLong())
    }
    return SignatureData(signedData, cmsData)
  }
}
