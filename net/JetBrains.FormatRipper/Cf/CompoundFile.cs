using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using JetBrains.Util;

namespace JetBrains.SignatureVerifier.Cf
{
  public class CompoundFile
  {
    private readonly Stream _stream;

    // Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft
    private readonly CompoundFileHeader _header;
    private readonly List<uint> _sectFat;
    private readonly List<uint> _fat;
    private readonly List<uint> _miniFat;
    private const int DirectoryEntrySize = 0x80;

    public CompoundFile(Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");
      _stream = stream;
      using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);
      _header = new CompoundFileHeader(reader);
      _sectFat = readSectFat(reader);
      _fat = readFat(reader);
      _miniFat = readMiniFat(reader);
    }

    public byte[] GetStreamData(byte[] entryName)
    {
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      var dirEntry = findStreamByName(reader, entryName);
      if (dirEntry != null)
        return readStreamData(reader, dirEntry.Value);
      return null;
    }

    public byte[] GetStreamData(DirectoryEntry entry)
    {
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      return readStreamData(reader, entry);
    }

    public List<DirectoryEntry> GetStreamDirectoryEntries()
    {
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      var res = new List<DirectoryEntry>();
      var nextSect = _header.SectDirStart;

      while (nextSect != SpecialSectors.ENDOFCHAIN)
      {
        reader.Jump(_header.GetSectorOffset(nextSect));

        for (var dirIndex = 0; dirIndex < _header.SectorSize / DirectoryEntrySize; dirIndex++)
        {
          var dirEntry = readDirectoryEntry(reader);

          if (dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
            res.Add(dirEntry);
        }

        nextSect = _fat[(int)nextSect];
      }

      return res;
    }

    public byte[] GetRootDirectoryClsid()
    {
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      return findRootDirectoryEntry(reader)?.Clsid;
    }

    private List<uint> readFat(BinaryReader reader)
    {
      var res = new List<uint>();

      foreach (var sect in _sectFat)
      {
        reader.Jump(_header.GetSectorOffset(sect));

        for (int j = 0; j < _header.SectorSize >> 2; j++)
        {
          res.Add(reader.ReadUInt32());
        }
      }

      return res;
    }

    private List<uint> readSectFat(BinaryReader reader)
    {
      var res = new List<uint>((int)_header.SectFatCount);

      for (var i = 0; i < 109; i++)
      {
        var sector = reader.ReadUInt32();

        if (sector == SpecialSectors.FREESECT)
          break;

        res.Add(sector);
      }

      var nextSect = _header.SectDifStart;
      var difatSectorsCount = (_header.SectorSize >> 2) - 1;

      while (nextSect != SpecialSectors.ENDOFCHAIN)
      {
        reader.Jump(_header.GetSectorOffset(nextSect));

        for (int i = 0; i < difatSectorsCount; i++)
        {
          var sector = reader.ReadUInt32();

          if (sector == SpecialSectors.FREESECT
              || sector == SpecialSectors.ENDOFCHAIN)
          {
            return res;
          }

          res.Add(sector);
        }

        //next sector in the difat chain
        nextSect = reader.ReadUInt32();
      }

      return res;
    }

    private DirectoryEntry? findRootDirectoryEntry(BinaryReader reader)
    {
      if (_header.SectDirStart != SpecialSectors.ENDOFCHAIN)
      {
        reader.Jump(_header.GetSectorOffset(_header.SectDirStart));
        return readDirectoryEntry(reader);
      }

      return null;
    }

    private DirectoryEntry? findStreamByName(BinaryReader reader, byte[] streamName)
    {
      var nextSect = _header.SectDirStart;

      while (nextSect != SpecialSectors.ENDOFCHAIN)
      {
        reader.Jump(_header.GetSectorOffset(nextSect));

        for (var dirIndex = 0; dirIndex < _header.SectorSize / DirectoryEntrySize; dirIndex++)
        {
          var dirEntry = readDirectoryEntry(reader);

          if (streamName.SequenceEqual(dirEntry.Name) && dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
            return dirEntry;
        }

        nextSect = _fat[(int)nextSect];
      }

      return null;
    }

    private byte[] readStreamData(BinaryReader reader, DirectoryEntry dirEntry)
    {
      if (dirEntry.SizeLow <= _header.MiniSectorCutoff)
      {
        var rootDirectoryEntry = findRootDirectoryEntry(reader);

        if (rootDirectoryEntry?.EntryType != DirectoryEntryType.STGTY_ROOT)
          throw new InvalidDataException("Invalid format. Root directory entry not found");

        var miniStreamStartSector = rootDirectoryEntry.Value.StartSect;
        var miniStreamSectorOffset = _header.GetSectorOffset(miniStreamStartSector);
        return readStreamData(reader, _miniFat, dirEntry.SizeLow, dirEntry.StartSect, _header.MiniSectorSize, miniStreamSectorOffset);
      }

      return readStreamData(reader, _fat, dirEntry.SizeLow, dirEntry.StartSect, _header.SectorSize, 0);
    }

    private byte[] readStreamData(BinaryReader reader, List<uint> fat, uint size, uint startSect, uint sectorSize, uint baseOffset)
    {
      var res = new byte[size];
      var read = 0;
      var nextSect = startSect;

      while (nextSect != SpecialSectors.ENDOFCHAIN)
      {
        var streamOffset = baseOffset;

        if (sectorSize == _header.MiniSectorSize)
          streamOffset += nextSect << _header.MiniSectorShift;
        else
          streamOffset = _header.GetSectorOffset(nextSect);

        reader.Jump(streamOffset);
        var toRead = Math.Min(size - read, sectorSize);
        var data = reader.ReadBytes((int)toRead);
        Buffer.BlockCopy(data, 0, res, read, data.Length);
        read += data.Length;
        nextSect = fat[(int)nextSect];
      }

      return res;
    }

    private List<uint> readMiniFat(BinaryReader reader)
    {
      var miniFat = new List<uint>();
      var nextSect = _header.SectMiniFatStart;

      while (nextSect != SpecialSectors.ENDOFCHAIN)
      {
        reader.Jump(_header.GetSectorOffset(nextSect));

        for (int j = 0; j < _header.SectorSize >> 2; j++)
          miniFat.Add(reader.ReadUInt32());

        nextSect = _fat[(int)nextSect];
      }

      return miniFat;
    }

    private DirectoryEntry readDirectoryEntry(BinaryReader reader)
    {
      return new DirectoryEntry(reader);
    }
  }

  struct CompoundFileHeader
  {
    /// <summary>
    /// Size of sectors in power-of-two
    /// </summary>
    public readonly ushort SectorShift;

    /// <summary>
    /// Size of mini-sectors in power-of-two, typically 6 indicating 64-byte mini-sectors
    /// </summary>
    public readonly ushort MiniSectorShift;

    /// <summary>
    /// Number of SECTs in directory chain for 4 KB sectors, must be zero for 512-byte sectors
    /// </summary>
    public readonly uint SectDirCount;

    /// <summary>
    /// Number of SECTs in the FAT chain
    /// </summary>
    public readonly uint SectFatCount;

    /// <summary>
    /// First SECT in the directory chain
    /// </summary>
    public readonly uint SectDirStart;

    /// <summary>
    /// Maximum size for a mini stream
    /// </summary>
    public readonly uint MiniSectorCutoff;

    /// <summary>
    /// First SECT in the MiniFAT chain
    /// </summary>
    public readonly uint SectMiniFatStart;

    /// <summary>
    /// Number of SECTs in the MiniFAT chain
    /// </summary>
    public readonly uint SectMiniFatCount;

    /// <summary>
    /// First SECT in the DIFAT chain
    /// </summary>
    public readonly uint SectDifStart;

    /// <summary>
    /// Number of SECTs in the DIFAT chain
    /// </summary>
    public readonly uint SectDifCount;

    public CompoundFileHeader(BinaryReader reader)
    {
      if (reader.ReadUInt64() != 0xE11AB1A1E011CFD0)
        throw new InvalidDataException("Invalid format. Unknown magic value");

      reader.Skip(18); //skip CLSID & Minor version
      var version = reader.ReadUInt16();
      var byteOrder = reader.ReadUInt16();

      if (byteOrder != 0xFFFE)
        throw new InvalidDataException("Invalid format. Only Little endian is expected");

      SectorShift = reader.ReadUInt16();

      if (!(version == 3 && SectorShift == 9
            || version == 4 && SectorShift == 0xC))
        throw new InvalidDataException("Invalid format. Version and sector size are incompatible");

      MiniSectorShift = reader.ReadUInt16();

      if (MiniSectorShift != 6)
        throw new InvalidDataException("Invalid format. Mini Stream Sector Size must be equal 6");

      reader.Skip(6); //skip "Reserved"
      SectDirCount = reader.ReadUInt32();
      SectFatCount = reader.ReadUInt32();
      SectDirStart = reader.ReadUInt32();
      reader.Skip(4);
      MiniSectorCutoff = reader.ReadUInt32();
      SectMiniFatStart = reader.ReadUInt32();
      SectMiniFatCount = reader.ReadUInt32();
      SectDifStart = reader.ReadUInt32();
      SectDifCount = reader.ReadUInt32();
    }

    public uint SectorSize => 1u << SectorShift;

    public uint MiniSectorSize => 1u << MiniSectorShift;

    public readonly uint GetSectorOffset(uint sect) => (sect + 1u) << SectorShift;
  }

  public struct DirectoryEntry
  {
    public readonly byte[] Name;
    public readonly byte EntryType;
    public readonly byte[] Clsid;
    public readonly uint StartSect;
    public readonly uint SizeLow;
    public readonly uint SizeHigh;

    public DirectoryEntry(BinaryReader reader)
    {
      var _name = reader.ReadBytes(64);
      var _nameLen = reader.ReadUInt16();

      if (_nameLen > 2)
      {
        Name = new byte[_nameLen - 2];
        Buffer.BlockCopy(_name, 0, Name, 0, _nameLen - 2);
      }
      else
      {
        Name = Array.Empty<byte>();
      }

      EntryType = reader.ReadByte();

      if (EntryType == DirectoryEntryType.STGTY_ROOT)
      {
        reader.Skip(13);
        Clsid = reader.ReadBytes(16);
        reader.Skip(20);
      }
      else
      {
        Clsid = null;
        reader.Skip(49);
      }

      StartSect = reader.ReadUInt32();
      SizeLow = reader.ReadUInt32();
      SizeHigh = reader.ReadUInt32();
    }
  }

  static class SpecialSectors
  {
    /// <summary>
    /// Specifies a DIFAT sector in the FAT
    /// </summary>
    public static readonly uint DIFSECT = 0xFFFFFFFC;

    /// <summary>
    /// Specifies a FAT sector in the FAT
    /// </summary>
    public static readonly uint FATSECT = 0xFFFFFFFD;

    /// <summary>
    /// End of a linked chain of sectors
    /// </summary>
    public static readonly uint ENDOFCHAIN = 0xFFFFFFFE;

    /// <summary>
    /// Specifies an unallocated sector in the FAT, Mini FAT, or DIFAT
    /// </summary>
    public static readonly uint FREESECT = 0xFFFFFFFF;
  }

  static class DirectoryEntryType
  {
    /// <summary>
    /// Unknown storage type
    /// </summary>
    public static readonly byte STGTY_INVALID = 0;

    /// <summary>
    /// Element is a storage object
    /// </summary>
    public static readonly byte STGTY_STORAGE = 1;

    /// <summary>
    /// Element is a stream object
    /// </summary>
    public static readonly byte STGTY_STREAM = 2;

    /// <summary>
    /// Element is an ILockBytes object
    /// </summary>
    public static readonly byte STGTY_LOCKBYTES = 3;

    /// <summary>
    /// Element is an IPropertyStorage object
    /// </summary>
    public static readonly byte STGTY_PROPERTY = 4;

    /// <summary>
    /// Element is a root storage
    /// </summary>
    public static readonly byte STGTY_ROOT = 5;
  }
}