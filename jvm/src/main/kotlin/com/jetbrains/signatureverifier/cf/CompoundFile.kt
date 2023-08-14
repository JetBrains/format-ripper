package com.jetbrains.signatureverifier.cf

import com.jetbrains.signatureverifier.DataInfo
import com.jetbrains.signatureverifier.DataValue
import com.jetbrains.signatureverifier.InvalidDataException
import com.jetbrains.signatureverifier.serialization.ByteArraySerializer
import com.jetbrains.signatureverifier.serialization.toByteArray
import com.jetbrains.signatureverifier.serialization.toHexString
import com.jetbrains.util.*
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SeekableByteChannel
import java.text.ParseException

open class CompoundFile {
  // Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft

  companion object {
    private val DirectoryEntrySize = 0x80u

    @Serializable
    data class SectFatMetaInfo(
      var splitIndex: Int = 0,
      var freeSect: UInt? = null,
    )

    @Serializable
    data class CompoundFileMetaInfo(
      val header: CompoundFileHeader,
      val sectFat: List<UInt>,
      val fat: List<UInt>,
      val miniFat: List<UInt>
    )
  }

  private val _stream: SeekableByteChannel
  private val _header: CompoundFileHeader
  private val _sectFat: List<UInt>
  private val _fat: List<UInt>
  private val _miniFat: List<UInt>
  private val _metaInfo: CompoundFileMetaInfo


  constructor(metaInfo: CompoundFileMetaInfo, stream: SeekableByteChannel) {
    _stream = stream

    _header = metaInfo.header
    CompoundFileHeader.writeHeader(_stream, _header.metaInfo)

    _sectFat = metaInfo.sectFat
    writeSectFat(_sectFat)

    _fat = metaInfo.fat
    writeFat()

    _miniFat = metaInfo.miniFat
    writeMiniFat()

    _metaInfo = CompoundFileMetaInfo(
      _header, _sectFat, _fat, _miniFat
    )
  }

  constructor(stream: SeekableByteChannel) {
    if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
      throw ParseException("Only Little endian is expected", 0)

    _stream = stream
    val reader = BinaryReader(stream.Rewind())
    _header = CompoundFileHeader(_stream, reader)

    _sectFat = readSectFat(reader)

    _fat = readFat(reader)
    _miniFat = readMiniFat(reader)

    _metaInfo = CompoundFileMetaInfo(
      _header, _sectFat, _fat, _miniFat
    )
  }

  fun getMetaInfo(): CompoundFileMetaInfo = _metaInfo


  fun putEntries(
    data: List<Pair<DirectoryEntry, ByteArray>>,
    miniStreamStartSector: Int,
    wipe: Boolean = false
  ) {
    putDirectoryEntries(data.map { it.first }, wipe)
    putStreamData(data, miniStreamStartSector, wipe)
  }

  private fun putDirectoryEntries(
    data: List<DirectoryEntry>,
    wipe: Boolean = false
  ) {
    var nextSect = _header.SectDirStart
    val dataIterator = data.iterator()

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      repeat((_header.SectorSize / DirectoryEntrySize).toInt().coerceAtMost(data.size)) {
        val entry = dataIterator.next()
        if (wipe) {
          wipeDirectoryEntry()
        } else {
          writeDirectoryEntry(entry)
        }
      }
      nextSect = _fat[nextSect.toInt()]
    }
  }

  private fun putStreamData(
    data: List<Pair<DirectoryEntry, ByteArray>>,
    miniStreamStartSector: Int,
    wipe: Boolean = false
  ) {
    val reader = BinaryReader(_stream)
    var nextSect = _header.SectDirStart
    val dataIterator = data.iterator()

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      repeat((_header.SectorSize / DirectoryEntrySize).toInt().coerceAtMost(data.size)) {
        val entry = dataIterator.next()
        if (wipe) {
          writeStreamData(entry.first, ByteArray(entry.second.size), miniStreamStartSector)
        } else if (entry.second.isNotEmpty() && entry.first.Name.toHexString() != MsiFile.rootEntryName.toHexString()) {
          writeStreamData(entry.first, entry.second, miniStreamStartSector)
        }
      }

      nextSect = _fat[nextSect.toInt()]
    }
  }

  fun getRootEntry(visitedSectors: MutableList<Pair<Int, Int>>? = null) = BinaryReader(_stream).let { reader ->
    findRootDirectoryEntry(reader)!!.let {
      Pair(it, readStreamData(reader, it, visitedSectors))
    }
  }

  fun getEntries(visitedSectors: MutableList<Pair<Int, Int>>? = null): List<Pair<DirectoryEntry, ByteArray>> {
    val res = BinaryReader(_stream).let { reader ->
      GetStreamDirectoryEntries(addAll = true)
        .map {
          Pair(it, readStreamData(reader, it, visitedSectors))
        }
    }
    return res
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

  fun GetStreamDirectoryEntries(addAll: Boolean = false): List<DirectoryEntry> {
    val reader = BinaryReader(_stream)
    val res = mutableListOf<DirectoryEntry>()
    var nextSect = _header.SectDirStart

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (dirIndex in 0 until (_header.SectorSize / DirectoryEntrySize).toInt()) {
        val dirEntry = readDirectoryEntry(reader)

        if (dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM || addAll)
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

  private fun writeFat() {
    val iterator = _fat.iterator()
    _sectFat.forEach { sect ->
      _stream.Jump(_header.GetSectorOffset(sect))
      for (j in 0 until (_header.SectorSize shr 2).toInt()) {
        _stream.write(ByteBuffer.wrap(iterator.next().toInt().toByteArray()))
      }
    }
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

  fun writeSectFat(sectFat: List<UInt>) {
    sectFat.forEach {
      _stream.write(ByteBuffer.wrap(it.toInt().toByteArray().copyOf(UInt.SIZE_BYTES)))
    }
  }


  private fun readSectFat(reader: BinaryReader): MutableList<UInt> {
    val res = mutableListOf<UInt>()
    for (i in 0 until 109) {
      val sector = reader.ReadUInt32()

      if (sector.toLong() == SpecialSectors.FREESECT) {
        break
      }

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

  private fun readStreamData(
    reader: BinaryReader,
    dirEntry: DirectoryEntry,
    visitedSectors: MutableList<Pair<Int, Int>>? = null
  ): ByteArray {
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
        miniStreamSectorOffset,
        visitedSectors
      )
    }
    return readStreamData(
      reader,
      _fat,
      dirEntry.SizeLow,
      dirEntry.StartSect,
      _header.SectorSize,
      0u,
      visitedSectors
    )
  }

  private fun readStreamData(
    reader: BinaryReader,
    fat: List<UInt>,
    size: UInt,
    startSect: UInt,
    sectorSize: UInt,
    baseOffset: UInt,
    visitedSectors: MutableList<Pair<Int, Int>>? = null
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
      visitedSectors?.add(streamOffset.toInt() to _stream.position().toInt())

      nextSect = fat[nextSect.toInt()]
    }
    return res
  }

  private fun writeStreamData(
    dirEntry: DirectoryEntry,
    data: ByteArray,
    miniStreamStartSector: Int
  ) {
    if (dirEntry.SizeLow <= _header.MiniSectorCutoff) {
      val miniStreamSectorOffset = _header.GetSectorOffset(miniStreamStartSector.toUInt())
      return writeStreamData(
        _miniFat,
        dirEntry.SizeLow,
        dirEntry.StartSect,
        _header.MiniSectorSize,
        miniStreamSectorOffset,
        data
      )
    }
    return writeStreamData(_fat, dirEntry.SizeLow, dirEntry.StartSect, _header.SectorSize, 0u, data)
  }

  private fun writeStreamData(
    fat: List<UInt>,
    size: UInt,
    startSect: UInt,
    sectorSize: UInt,
    baseOffset: UInt,
    data: ByteArray
  ) {
    var cursor = 0
    var nextSect = startSect

    while (nextSect.toLong() != SpecialSectors.ENDOFCHAIN) {
      var streamOffset = baseOffset

      if (sectorSize == _header.MiniSectorSize)
        streamOffset += nextSect shl _header.MiniSectorShift
      else
        streamOffset = _header.GetSectorOffset(nextSect)

      _stream.Jump(streamOffset)

      val toWrite = Math.min(size.toInt() - cursor, sectorSize.toInt())
      _stream.write(
        ByteBuffer.wrap(
          data.sliceArray(cursor until cursor + toWrite)
        )
      )
      cursor += toWrite
      nextSect = fat[nextSect.toInt()]
    }
  }

  private fun writeMiniFat() {
    var nextSect = _header.SectMiniFatStart
    val iterator = _miniFat.iterator()

    while (iterator.hasNext()) {
      _stream.Jump(_header.GetSectorOffset(nextSect))

      for (j in 0 until (_header.SectorSize shr 2).toInt()) {
        _stream.write(ByteBuffer.wrap(iterator.next().toInt().toByteArray()))
      }

      nextSect = _fat[nextSect.toInt()]
    }
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

  private fun wipeDirectoryEntry() {
    _stream.write(ByteBuffer.wrap(ByteArray(128)))
  }

  private fun writeDirectoryEntry(entry: DirectoryEntry) {
    _stream.write(ByteBuffer.wrap(entry.Name.copyOf(64)))
    _stream.write(
      ByteBuffer.wrap(
        entry.NameLen.toInt().toByteArray().copyOf(UShort.SIZE_BYTES)
      )
    )

    _stream.write(ByteBuffer.wrap(listOf(entry.EntryType).toByteArray()))

    if (entry.EntryType == DirectoryEntryType.STGTY_ROOT) {
      assert(entry.metaBytes[0].size == 13)
      assert(entry.metaBytes[1].size == 20)
      _stream.write(ByteBuffer.wrap(entry.metaBytes[0]))
      _stream.write(ByteBuffer.wrap(entry.Clsid!!.copyOf(16)))
      _stream.write(ByteBuffer.wrap(entry.metaBytes[1]))
    } else {
      assert(entry.metaBytes[0].size == 49)
      _stream.write(ByteBuffer.wrap(entry.metaBytes[0]))
    }

    _stream.write(ByteBuffer.wrap(entry.StartSect.toInt().toByteArray()))
    _stream.write(ByteBuffer.wrap(entry.SizeLow.toInt().toByteArray()))
    _stream.write(ByteBuffer.wrap(entry.SizeHigh.toInt().toByteArray()))
  }
}

@Serializable
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

  val metaInfo: CompoundFileHeaderMetaInfo

  companion object {
    @Serializable
    data class CompoundFileHeaderMetaInfo(
      var CLSID: DataValue = DataValue(),
      var minorVersion: DataValue = DataValue(),
      var version: DataValue = DataValue(),
      var byteOrder: DataValue = DataValue(),
      var sectorShift: DataValue = DataValue(),
      var miniSectorShift: DataValue = DataValue(),
      var reserved: DataValue = DataValue(),
      var sectDirCount: DataValue = DataValue(),
      var sectFatCount: DataValue = DataValue(),
      var sectDirStart: DataValue = DataValue(),
      var reserved2: DataValue = DataValue(),
      var miniSectorCutoff: DataValue = DataValue(),
      var sectMiniFatStart: DataValue = DataValue(),
      var sectMiniFatCount: DataValue = DataValue(),
      var sectDifStart: DataValue = DataValue(),
      var sectDifCount: DataValue = DataValue(),
    )

    fun writeHeader(stream: SeekableByteChannel, metaInfo: CompoundFileHeaderMetaInfo) {
      listOf(
        metaInfo.CLSID,
        metaInfo.minorVersion,
        metaInfo.version,
        metaInfo.byteOrder,
        metaInfo.sectorShift,
        metaInfo.miniSectorShift,
        metaInfo.reserved,
        metaInfo.sectDirCount,
        metaInfo.sectFatCount,
        metaInfo.sectDirStart,
        metaInfo.reserved2,
        metaInfo.miniSectorCutoff,
        metaInfo.sectMiniFatStart,
        metaInfo.sectMiniFatCount,
        metaInfo.sectDifStart,
        metaInfo.sectDifCount
      ).forEach {
        stream.Seek(it.dataInfo.Offset.toLong(), SeekOrigin.Begin)
        stream.write(ByteBuffer.wrap(it.value))
      }
    }
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is CompoundFileHeader) return false

    return SectorShift == other.SectorShift &&
      MiniSectorShift == other.MiniSectorShift &&
      SectDirCount == other.SectDirCount &&
      SectFatCount == other.SectFatCount &&
      SectDirStart == other.SectDirStart &&
      MiniSectorCutoff == other.MiniSectorCutoff &&
      SectMiniFatStart == other.SectMiniFatStart &&
      SectMiniFatCount == other.SectMiniFatCount &&
      SectDifStart == other.SectDifStart &&
      SectDifCount == other.SectDifCount &&
      metaInfo == other.metaInfo
  }

  constructor(stream: SeekableByteChannel, reader: BinaryReader) {
    //magic 0xE11AB1A1E011CFD0
    if (reader.ReadInt64() != -2226271756974174256)
      throw InvalidDataException("Invalid format. Unknown magic value")

    metaInfo = CompoundFileHeaderMetaInfo()

    metaInfo.CLSID =
      DataValue(DataInfo(stream.position().toInt(), 16), reader.ReadBytes(16))

    metaInfo.minorVersion =
      DataValue(DataInfo(stream.position().toInt(), UShort.SIZE_BYTES), reader.ReadUInt16().toInt().toByteArray())

    var position = stream.position().toInt()
    val version = reader.ReadUInt16().toInt()
    metaInfo.version = DataValue(DataInfo(position, UShort.SIZE_BYTES), version.toByteArray())

    position = stream.position().toInt()
    val byteOrder = reader.ReadUInt16().toInt()
    metaInfo.byteOrder = DataValue(DataInfo(position, UShort.SIZE_BYTES), byteOrder.toByteArray())

    if (byteOrder != 0xFFFE)
      throw InvalidDataException("Invalid format. Only Little endian is expected")

    position = stream.position().toInt()
    SectorShift = reader.ReadUInt16().toInt()
    metaInfo.sectorShift = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectorShift.toByteArray())

    if (!(version == 3 && SectorShift == 9 || version == 4 && SectorShift == 0xC))
      throw InvalidDataException("Invalid format. Version and sector size are incompatible")

    position = stream.position().toInt()
    MiniSectorShift = reader.ReadUInt16().toInt()
    metaInfo.miniSectorShift = DataValue(DataInfo(position, UShort.SIZE_BYTES), MiniSectorShift.toByteArray())

    if (MiniSectorShift != 6)
      throw InvalidDataException("Invalid format. Mini Stream Sector Size must be equal 6")

    metaInfo.reserved = DataValue(
      DataInfo(stream.position().toInt(), 6),
      reader.ReadBytes(6).copyOf(6)
    )

    position = stream.position().toInt()
    SectDirCount = reader.ReadUInt32()
    metaInfo.sectDirCount = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectDirCount.toInt().toByteArray())

    position = stream.position().toInt()
    SectFatCount = reader.ReadUInt32()
    metaInfo.sectFatCount = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectFatCount.toInt().toByteArray())

    position = stream.position().toInt()
    SectDirStart = reader.ReadUInt32()
    metaInfo.sectDirStart = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectDirStart.toInt().toByteArray())

    metaInfo.reserved2 = DataValue(
      DataInfo(stream.position().toInt(), 4),
      reader.ReadBytes(4).copyOf(4)
    )

    position = stream.position().toInt()
    MiniSectorCutoff = reader.ReadUInt32()
    metaInfo.miniSectorCutoff = DataValue(DataInfo(position, UShort.SIZE_BYTES), MiniSectorCutoff.toInt().toByteArray())

    position = stream.position().toInt()
    SectMiniFatStart = reader.ReadUInt32()
    metaInfo.sectMiniFatStart = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectMiniFatStart.toInt().toByteArray())

    position = stream.position().toInt()
    SectMiniFatCount = reader.ReadUInt32()
    metaInfo.sectMiniFatCount = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectMiniFatCount.toInt().toByteArray())

    position = stream.position().toInt()
    SectDifStart = reader.ReadUInt32()
    metaInfo.sectDifStart = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectDifStart.toInt().toByteArray())

    position = stream.position().toInt()
    SectDifCount = reader.ReadUInt32()
    metaInfo.sectDifCount = DataValue(DataInfo(position, UShort.SIZE_BYTES), SectDifCount.toInt().toByteArray())
  }

  val SectorSize: UInt
    get() = 1u shl SectorShift

  val MiniSectorSize: UInt
    get() = 1u shl MiniSectorShift

  fun GetSectorOffset(sect: UInt): UInt = (sect + 1u) shl SectorShift
}

@Serializable
class DirectoryEntry {
  @Serializable(ByteArraySerializer::class)
  val Name: ByteArray
  val NameLen: UShort
  val EntryType: Byte

  @Serializable(ByteArraySerializer::class)
  val Clsid: ByteArray?
  val StartSect: UInt
  val SizeLow: UInt
  val SizeHigh: UInt
  val metaBytes: MutableList<@Serializable(ByteArraySerializer::class) ByteArray> = mutableListOf()

  constructor(stream: SeekableByteChannel, reader: BinaryReader) {
    val _name = reader.ReadBytes(64)
    NameLen = reader.ReadUInt16()

    if (NameLen > 2u) {
      Name = ByteArray((NameLen.toInt() - 2).coerceAtMost(_name.size))
      _name.copyInto(Name, 0, 0, Name.size)
    } else {
      Name = ByteArray(0)
    }

    EntryType = reader.ReadByte()

    if (EntryType == DirectoryEntryType.STGTY_ROOT) {
      metaBytes.add(reader.ReadBytes(13).copyOf(13))
      Clsid = reader.ReadBytes(16)
      metaBytes.add(reader.ReadBytes(20).copyOf(20))
    } else {
      Clsid = null
      metaBytes.add(reader.ReadBytes(49).copyOf(49))
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
