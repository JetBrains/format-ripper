package com.jetbrains.signatureverifier.cf

import com.jetbrains.signatureverifier.InvalidDataException
import com.jetbrains.util.BinaryReader
import com.jetbrains.util.Jump
import com.jetbrains.util.Rewind
import com.jetbrains.util.Skip
import java.nio.channels.SeekableByteChannel

open class CompoundFile {
  // Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft

  companion object {
    private val DirectoryEntrySize = 0x80u
  }

  private val _stream: SeekableByteChannel
  private val _header: CompoundFileHeader
  private val _sectFat: List<UInt>
  private val _fat: List<UInt>
  private val _miniFat: List<UInt>

  constructor(stream: SeekableByteChannel) {
    _stream = stream
    val reader = BinaryReader(stream.Rewind())
    _header = CompoundFileHeader(_stream, reader)
    _sectFat = readSectFat(reader)
    _fat = readFat(reader)
    _miniFat = readMiniFat(reader)
  }

  fun GetStreamData(entryName: ByteArray): ByteArray? {
    val reader = BinaryReader(_stream)
    val dirEntry = findStreamByName(reader, entryName)

    if (dirEntry != null)
      return readStreamData(reader, dirEntry)

    return null
  }

  fun GetStreamData(entry: DirectoryEntry): ByteArray? {
    val reader = BinaryReader(_stream)
    return readStreamData(reader, entry)
  }

  fun GetStreamDirectoryEntries(): List<DirectoryEntry> {
    val reader = BinaryReader(_stream)
    val res = mutableListOf<DirectoryEntry>()
    var nextSect = _header.SectDirStart

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (dirIndex in 0 until (_header.SectorSize / DirectoryEntrySize).toInt()) {
        val dirEntry = readDirectoryEntry(reader)

        if (dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
          res.add(dirEntry)
      }
      nextSect = _fat[nextSect.toInt()]
    }
    return res
  }

  fun GetRootDirectoryClsid(): ByteArray? {
    val reader = BinaryReader(_stream)
    return findRootDirectoryEntry(reader)?.Clsid
  }

  private fun readFat(reader: BinaryReader): List<UInt> {
    val res = mutableListOf<UInt>()

    for (sect in _sectFat) {
      _stream.Jump(_header.GetSectorOffset(sect))

      for (j in 0 until (_header.SectorSize shr 2).toInt()) {
        res.add(reader.ReadUInt32())
      }
    }
    return res
  }

  private fun readSectFat(reader: BinaryReader): MutableList<UInt> {
    val res = mutableListOf<UInt>()

    for (i in 0 until 109) {
      val sector = reader.ReadUInt32()

      if (sector.toLong() == SpecialSectors.FREESECT)
        break

      res.add(sector)
    }

    var nextSect = _header.SectDifStart
    val difatSectorsCount = (_header.SectorSize shr 2) - 1u

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (i in 0 until difatSectorsCount.toInt()) {
        val sector = reader.ReadUInt32()

        if (sector.toLong() == SpecialSectors.FREESECT || sector.toLong() == SpecialSectors.ENDOFCHAIN) {
          return res
        }

        res.add(sector)
      }
      //next sector in the difat chain
      nextSect = reader.ReadUInt32()
    }
    return res
  }

  private fun findRootDirectoryEntry(reader: BinaryReader): DirectoryEntry? {
    if (_header.SectDirStart.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(_header.SectDirStart))
      return readDirectoryEntry(reader)
    }
    return null
  }

  private fun findStreamByName(reader: BinaryReader, streamName: ByteArray): DirectoryEntry? {
    var nextSect = _header.SectDirStart

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (dirIndex in 0 until (_header.SectorSize / DirectoryEntrySize).toInt()) {
        val dirEntry = readDirectoryEntry(reader)

        if (streamName.contentEquals(dirEntry.Name) && dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
          return dirEntry
      }
      nextSect = _fat[nextSect.toInt()]
    }
    return null
  }

  private fun readStreamData(reader: BinaryReader, dirEntry: DirectoryEntry): ByteArray {
    if (dirEntry.SizeLow <= _header.MiniSectorCutoff) {
      val rootDirectoryEntry = findRootDirectoryEntry(reader)

      if (rootDirectoryEntry?.EntryType != DirectoryEntryType.STGTY_ROOT)
        throw InvalidDataException("Invalid format. Root directory entry not found")

      val miniStreamStartSector = rootDirectoryEntry.StartSect
      val miniStreamSectorOffset = _header.GetSectorOffset(miniStreamStartSector)
      return readStreamData(
        reader,
        _miniFat,
        dirEntry.SizeLow,
        dirEntry.StartSect,
        _header.MiniSectorSize,
        miniStreamSectorOffset
      )
    }
    return readStreamData(reader, _fat, dirEntry.SizeLow, dirEntry.StartSect, _header.SectorSize, 0u)
  }

  private fun readStreamData(
    reader: BinaryReader,
    fat: List<UInt>,
    size: UInt,
    startSect: UInt,
    sectorSize: UInt,
    baseOffset: UInt
  ): ByteArray {
    val res = ByteArray(size.toInt())
    var read = 0
    var nextSect = startSect

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      var streamOffset = baseOffset

      if (sectorSize == _header.MiniSectorSize)
        streamOffset += nextSect shl _header.MiniSectorShift
      else
        streamOffset = _header.GetSectorOffset(nextSect)

      _stream.Jump(streamOffset)
      val toRead = Math.min(size.toInt() - read, sectorSize.toInt())
      val data = reader.ReadBytes(toRead)
      data.copyInto(res, read)
      read += data.count()
      nextSect = fat[nextSect.toInt()]
    }
    return res
  }

  private fun readMiniFat(reader: BinaryReader): MutableList<UInt> {
    val miniFat = mutableListOf<UInt>()
    var nextSect = _header.SectMiniFatStart

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (j in 0 until (_header.SectorSize shr 2).toInt()) {
        miniFat.add(reader.ReadUInt32())
      }

      nextSect = _fat[nextSect.toInt()]
    }
    return miniFat
  }

  private fun readDirectoryEntry(reader: BinaryReader): DirectoryEntry {
    return DirectoryEntry(_stream, reader)
  }
}

open class CompoundFileHeader {
  /**
   * Size of sectors in power-of-two
   */
  val SectorShift: Int

  /**
   * Size of mini-sectors in power-of-two, typically 6 indicating 64-byte mini-sectors
   */
  val MiniSectorShift: Int

  /**
   * Number of SECTs in directory chain for 4 KB sectors, must be zero for 512-byte sectors
   */
  val SectDirCount: UInt

  /**
   * Number of SECTs in the FAT chain
   */
  val SectFatCount: UInt

  /**
   * First SECT in the directory chain
   */
  val SectDirStart: UInt

  /**
   * Maximum size for a mini stream
   */
  val MiniSectorCutoff: UInt

  /**
   * First SECT in the MiniFAT chain
   */
  val SectMiniFatStart: UInt

  /**
   * Number of SECTs in the MiniFAT chain
   */
  val SectMiniFatCount: UInt

  /**
   * First SECT in the DIFAT chain
   */
  val SectDifStart: UInt

  /**
   * Number of SECTs in the DIFAT chain
   */
  val SectDifCount: UInt

  constructor(stream: SeekableByteChannel, reader: BinaryReader) {
    //magic 0xE11AB1A1E011CFD0
    if (reader.ReadInt64() != -2226271756974174256)
      throw InvalidDataException("Invalid format. Unknown magic value")

    stream.Skip(18) //skip CLSID & Minor version

    val version = reader.ReadUInt16().toInt()
    val byteOrder = reader.ReadUInt16().toInt()

    if (byteOrder != 0xFFFE)
      throw InvalidDataException("Invalid format. Only Little endian is expected")

    SectorShift = reader.ReadUInt16().toInt()

    if (!(version == 3 && SectorShift == 9 || version == 4 && SectorShift == 0xC))
      throw InvalidDataException("Invalid format. Version and sector size are incompatible")

    MiniSectorShift = reader.ReadUInt16().toInt()

    if (MiniSectorShift != 6)
      throw InvalidDataException("Invalid format. Mini Stream Sector Size must be equal 6")

    stream.Skip(6)//skip "Reserved"

    SectDirCount = reader.ReadUInt32()
    SectFatCount = reader.ReadUInt32()
    SectDirStart = reader.ReadUInt32()
    stream.Skip(4)
    MiniSectorCutoff = reader.ReadUInt32()
    SectMiniFatStart = reader.ReadUInt32()
    SectMiniFatCount = reader.ReadUInt32()
    SectDifStart = reader.ReadUInt32()
    SectDifCount = reader.ReadUInt32()
  }

  val SectorSize: UInt
    get() = 1u shl SectorShift

  val MiniSectorSize: UInt
    get() = 1u shl MiniSectorShift

  fun GetSectorOffset(sect: UInt): UInt = (sect + 1u) shl SectorShift
}

class DirectoryEntry {
  val Name: ByteArray
  val EntryType: Byte
  val Clsid: ByteArray?
  val StartSect: UInt
  val SizeLow: UInt
  val SizeHigh: UInt

  constructor(stream: SeekableByteChannel, reader: BinaryReader) {
    val _name = reader.ReadBytes(64)
    val _nameLen = reader.ReadUInt16()

    if (_nameLen > 2u) {
      Name = ByteArray(_nameLen.toInt() - 2)
      _name.copyInto(Name, 0, 0, (_nameLen - 2u).toInt())
    } else {
      Name = ByteArray(0)
    }

    EntryType = reader.ReadByte()

    if (EntryType == DirectoryEntryType.STGTY_ROOT) {
      stream.Skip(13)
      Clsid = reader.ReadBytes(16)
      stream.Skip(20)
    } else {
      Clsid = null
      stream.Skip(49)
    }

    StartSect = reader.ReadUInt32()
    SizeLow = reader.ReadUInt32()
    SizeHigh = reader.ReadUInt32()
  }
}

object SpecialSectors {
  /**
   * Specifies a DIFAT sector in the FAT
   */
  val DIFSECT = 0xFFFFFFFC

  /**
   * Specifies a FAT sector in the FAT
   */
  val FATSECT = 0xFFFFFFFD

  /**
   * End of a linked chain of sectors
   */
  val ENDOFCHAIN = 0xFFFFFFFE

  /**
   * Specifies an unallocated sector in the FAT, Mini FAT, or DIFAT
   */
  val FREESECT = 0xFFFFFFFF
}

object DirectoryEntryType {
  /**
   * Unknown storage type
   */
  val STGTY_INVALID = 0.toByte()

  /**
   * Element is a storage object
   */
  val STGTY_STORAGE = 1.toByte()

  /**
   * Element is a stream object
   */
  val STGTY_STREAM = 2.toByte()

  /**
   * Element is an ILockBytes object
   */
  val STGTY_LOCKBYTES = 3.toByte()

  /**
   * Element is an IPropertyStorage object
   */
  val STGTY_PROPERTY = 4.toByte()

  /**
   * Element is a root storage
   */
  val STGTY_ROOT = 5.toByte()
}
