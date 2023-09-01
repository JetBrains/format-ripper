package com.jetbrains.signatureverifier.macho

import com.jetbrains.signatureverifier.*
import com.jetbrains.util.*
import org.jetbrains.annotations.NotNull
import java.nio.channels.SeekableByteChannel
import java.text.ParseException

/**
 * Fat/Universal Mach-O file
 */
open class MachoArch {
  private val _stream: SeekableByteChannel
  private val _logger: ILogger

  /**
   * Initializes a new instance of the MachoArch
   *
   * @param stream  An input stream
   * @param logger  A logger
   * @exception ParseException  Indicates the byte order ("endianness")
   *     in which data is stored in this computer architecture is not Little Endian.
   */
  constructor(@NotNull stream: SeekableByteChannel, logger: ILogger? = null) {
    _stream = stream
    _logger = logger ?: NullLogger.Instance
  }

  /**
   * Return a list of macho architectures from fat-macho or one-item list for macho
   *
   * @return A collection of MachoFile
   */
  fun Extract(): Collection<MachoFile> {
    val reader = BinaryReader(_stream.Rewind())
    val masterMagic = reader.ReadUInt32().toLong() // mach_header::magic / mach_header64::magic / fat_header::magic
    if (MachoUtils.IsMacho(masterMagic))
      return listOf(getMachoData(_stream.Rewind()))
    else if (MachoUtils.IsFatMacho(masterMagic))
      return getFatMachoData(reader, masterMagic)
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
      // fat_header::nfat_arch
      val fatArchItems = mutableListOf<DataInfo>()
      if (isBe64 || isLe64)
        while (nFatArch-- > 0) {
          _stream.Seek(8, SeekOrigin.Current)
          fatArchItems.add(
            DataInfo(
              reader.ReadUInt64Le(isBe64).toInt(),  //fat_arch_64::offset
              reader.ReadUInt64Le(isBe64).toInt()   //fat_arch_64::size
            )
          )
          _stream.Seek(8, SeekOrigin.Current)
        }
      else
        while (nFatArch-- > 0) {
          _stream.Seek(8, SeekOrigin.Current)
          fatArchItems.add(
            DataInfo(
              reader.ReadUInt32Le(isBe32).toInt(),  //fat_arch::offset
              reader.ReadUInt32Le(isBe32).toInt()   //fat_arch::size
            )
          )

          _stream.Seek(4, SeekOrigin.Current)
        }
      return fatArchItems.map { s ->
        _stream.Seek(s.Offset.toLong(), SeekOrigin.Begin)
        MachoFile(reader.ReadBytes(s.Size))
      }.toList()
    }
    throw InvalidDataException("Unknown format")
  }

  private fun getMachoData(stream: SeekableByteChannel): MachoFile {
    return MachoFile(stream.ReadAll())
  }
}

