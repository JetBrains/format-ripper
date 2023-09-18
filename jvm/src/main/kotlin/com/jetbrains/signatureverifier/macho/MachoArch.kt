package com.jetbrains.signatureverifier.macho

import com.jetbrains.signatureverifier.DataInfo
import com.jetbrains.signatureverifier.ILogger
import com.jetbrains.signatureverifier.InvalidDataException
import com.jetbrains.signatureverifier.NullLogger
import com.jetbrains.signatureverifier.serialization.fileInfos.FatArchInfo32
import com.jetbrains.signatureverifier.serialization.fileInfos.FatArchInfo64
import com.jetbrains.signatureverifier.serialization.fileInfos.FatHeaderInfo
import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.nio.ByteOrder
import java.nio.channels.SeekableByteChannel
import java.text.ParseException

/**
 * Fat/Universal Mach-O file
 */
open class MachoArch {
  private val _stream: SeekableByteChannel
  private val _logger: ILogger
  val fatHeaderInfo: FatHeaderInfo

  /**
   * Initializes a new instance of the MachoArch
   *
   * @param stream  An input stream
   * @param logger  A logger
   * @exception ParseException  Indicates the byte order ("endianness")
   *     in which data is stored in this computer architecture is not Little Endian.
   */
  constructor(@NotNull stream: SeekableByteChannel, logger: ILogger? = null) {
    if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
      throw ParseException("Only Little endian is expected", 0)
    _stream = stream
    _logger = logger ?: NullLogger.Instance
    fatHeaderInfo = FatHeaderInfo()
  }

  /**
   * Return a list of macho architectures from fat-macho or one-item list for macho
   *
   * @return A collection of MachoFile
   */
  fun Extract(): Collection<MachoFile> {
    val reader = BinaryReader(_stream.Rewind())
    val masterMagic = reader.ReadUInt32().toLong() // mach_header::magic / mach_header64::magic / fat_header::magic
    fatHeaderInfo.magic = masterMagic.toUInt()
    return if (MachoUtils.IsMacho(masterMagic))
      listOf(getMachoData(_stream.Rewind()))
    else if (MachoUtils.IsFatMacho(masterMagic))
      getFatMachoData(reader, masterMagic)
    else
      throw InvalidDataException("Unknown format")
  }

  private fun getFatMachoData(reader: BinaryReader, magic: Long): Collection<MachoFile> {
    val isLe32 = magic == MachoConsts.FAT_MAGIC
    val isLe64 = magic == MachoConsts.FAT_MAGIC_64
    val isBe32 = magic == MachoConsts.FAT_CIGAM
    val isBe64 = magic == MachoConsts.FAT_CIGAM_64
    if (isLe32 || isLe64 || isBe32 || isBe64) {
      var nFatArch = reader.ReadUInt32Le(isBe32 || isBe64).toInt()
      fatHeaderInfo.fatArchSize = nFatArch.toUInt()
      fatHeaderInfo.isBe = isBe32 || isBe64
      // fat_header::nfat_arch
      val fatArchItems = mutableListOf<DataInfo>()
      if (isBe64 || isLe64)
        while (nFatArch-- > 0) {
          val cpuType = reader.ReadUInt32()
          val cpuSubType = reader.ReadUInt32()
          val offset = reader.ReadUInt64Le(isBe64)
          val size = reader.ReadUInt64Le(isBe64)
          fatArchItems.add(
            DataInfo(
              offset.toInt(),  //fat_arch_64::offset
              size.toInt()   //fat_arch_64::size
            )
          )
          val align = reader.ReadUInt64Le(isBe64)
          fatHeaderInfo.fatArchInfos.add(FatArchInfo64(cpuType, cpuSubType, offset, size, align))
        }
      else
        while (nFatArch-- > 0) {
          val cpuType = reader.ReadUInt32()
          val cpuSubType = reader.ReadUInt32()
          val offset = reader.ReadUInt32Le(isBe32)
          val size = reader.ReadUInt32Le(isBe32)
          fatArchItems.add(
            DataInfo(
              offset.toInt(),  //fat_arch::offset
              size.toInt()   //fat_arch::size
            )
          )

          val align = reader.ReadUInt32(isBe32)
          fatHeaderInfo.fatArchInfos.add(FatArchInfo32(cpuType, cpuSubType, offset, size, align))
        }
      return fatArchItems.map { s ->
        _stream.Seek(s.Offset.toLong(), SeekOrigin.Begin)
        MachoFile(reader.ReadBytes(s.Size), s.Size.toLong(), offset = s.Offset.toLong())
      }.toList()
    }
    throw InvalidDataException("Unknown format")
  }

  private fun getMachoData(stream: SeekableByteChannel): MachoFile {
    return MachoFile(stream.ReadAll(), _stream.size())
  }
}

