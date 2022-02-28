using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using JetBrains.Annotations;
using JetBrains.Util;

namespace JetBrains.SignatureVerifier.Macho
{
  public class MachoFile
  {
    private readonly Stream _stream;
    public uint Magic { get; private set; }
    public bool isLe32 => Magic == MachoConsts.MH_MAGIC;
    public bool isLe64 => Magic == MachoConsts.MH_MAGIC_64;
    public bool isBe32 => Magic == MachoConsts.MH_CIGAM;
    public bool isBe64 => Magic == MachoConsts.MH_CIGAM_64;
    public bool is32 => isLe32 || isBe32;
    public bool isBe => isBe32 || isBe64;

    private DataInfo ncmdsOffset = new(16, 8);
    private long ncmds;
    private long sizeofcmds;
    private long firstLoadCommandPosition;

    ///  <summary>
    /// Initializes a new instance of the <see cref="T:JetBrains.SignatureVerifier.MachoFile"></see>
    ///  </summary>
    ///  <param name="stream">An input stream</param>
    ///  <exception cref="PlatformNotSupportedException">Indicates the byte order ("endianness")
    ///  in which data is stored in this computer architecture is not Little Endian.</exception>
    ///  <exception cref="InvalidDataException">If the input stream not contain MachO</exception>
    public MachoFile([NotNull] Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");

      _stream = stream ?? throw new ArgumentNullException(nameof(stream));
      setMagic();
    }

    ///  <summary>
    /// Initializes a new instance of the <see cref="T:JetBrains.SignatureVerifier.MachoFile"></see>
    ///  </summary>
    ///  <param name="data">A raw data</param>
    ///  <exception cref="PlatformNotSupportedException">Indicates the byte order ("endianness")
    ///  in which data is stored in this computer architecture is not Little Endian.</exception>
    ///  <exception cref="InvalidDataException">If the input data not contain MachO</exception>
    public MachoFile([NotNull] byte[] data)
    {
      if (data == null)
        throw new ArgumentNullException(nameof(data));

      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");

      _stream = new MemoryStream(data);
      setMagic();
    }

    private void setMagic()
    {
      using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);
      Magic = reader.ReadUInt32(); // mach_header::magic / mach_header64::magic

      if (!MachoUtils.IsMacho(Magic))
        throw new InvalidDataException("Unknown format");

      _stream.Seek(ncmdsOffset.Offset, SeekOrigin.Begin);
      ncmds = ReadUtils.ReadUInt32Le(reader, isBe); // mach_header::ncmds / mach_header_64::ncmds
      sizeofcmds = ReadUtils.ReadUInt32Le(reader, isBe); // mach_header::sizeofcmds / mach_header_64::sizeofcmds
      firstLoadCommandPosition = _stream.Position + (is32 ? 4 : 8); // load_command[0]
    }

    public byte[] ComputeHash(string algName)
    {
      var (excludeRanges, hasLcCodeSignature) = getHashExcludeRanges();
      using var hash = IncrementalHash.CreateHash(new HashAlgorithmName(algName.ToUpper()));

      if (excludeRanges.Any())
      {
        using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);

        foreach (var dataInfo in excludeRanges)
        {
          var size = dataInfo.Offset - _stream.Position;

          if (size > 0)
          {
            hash.AppendData(reader.ReadBytes((int)size));
            _stream.Seek(dataInfo.Size, SeekOrigin.Current);
          }
        }

        hash.AppendData(_stream.ReadToEnd());

        //append the zero-inset to the end of data. codesign does it as well
        if (!hasLcCodeSignature)
        {
          var filesize = _stream.Position;
          var zeroInsetSize = filesize % 16;

          if (zeroInsetSize > 0)
          {
            zeroInsetSize = 16 - zeroInsetSize;
            hash.AppendData(new byte[zeroInsetSize]);
          }
        }
      }
      else
      {
        hash.AppendData(_stream.ReadAll());
      }

      return hash.GetHashAndReset();
    }

    private (List<DataInfo> excludeRanges, bool hasLcCodeSignature) getHashExcludeRanges()
    {
      var excludeRanges = new List<DataInfo> { ncmdsOffset };
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      _stream.Seek(firstLoadCommandPosition, SeekOrigin.Begin); // load_command[0]
      var hasLcCodeSignature = false;
      var _ncmds = ncmds;

      while (_ncmds-- > 0)
      {
        var cmpPosition = _stream.Position;
        var cmd = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmd
        var cmdsize = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmdsize

        if (cmd == MachoConsts.LC_SEGMENT || cmd == MachoConsts.LC_SEGMENT_64)
        {
          var segname = new string(reader.ReadChars(10));

          if (segname == "__LINKEDIT")
          {
            _stream.Seek(6, SeekOrigin.Current); //skip to end of segname which is 16 byte
            _stream.Seek(is32 ? 4 : 8, SeekOrigin.Current); //skip vmaddr

            var vmsizeOffset = new DataInfo((int)_stream.Position, is32 ? 4 : 8);
            excludeRanges.Add(vmsizeOffset);

            _stream.Seek((is32 ? 4 : 8) * 2, SeekOrigin.Current); //skip vmsize and fileoff

            var filesizeOffset = new DataInfo((int)_stream.Position, is32 ? 4 : 8);
            excludeRanges.Add(filesizeOffset);
          }
        }
        else if (cmd == MachoConsts.LC_CODE_SIGNATURE)
        {
          var lcCodeSignatureOffset = new DataInfo((int)cmpPosition, (int)cmdsize);
          excludeRanges.Add(lcCodeSignatureOffset);

          var lcCodeSignatureDataOffset =
            new DataInfo(
              (int)ReadUtils.ReadUInt32Le(reader, isBe), // load_command::dataoffn,
              (int)ReadUtils.ReadUInt32Le(reader, isBe)); // load_command::datasize);

          excludeRanges.Add(lcCodeSignatureDataOffset);
          hasLcCodeSignature = true;
        }

        _stream.Seek(cmdsize - (_stream.Position - cmpPosition), SeekOrigin.Current);
      }

      if (!hasLcCodeSignature)
      {
        //exclude the LC_CODE_SIGNATURE zero placeholder from hashing
        excludeRanges.Add(new DataInfo((int)(firstLoadCommandPosition + sizeofcmds), 16));
      }

      return (excludeRanges, hasLcCodeSignature);
    }

    /// <summary>
    /// Retrieve the signature data from MachO
    /// </summary>
    /// <exception cref="InvalidDataException">Indicates the data in the input stream does not correspond to MachO format or the signature data is malformed</exception>
    public SignatureData GetSignatureData()
    {
      try
      {
        return getMachoSignatureData();
      }
      catch (EndOfStreamException)
      {
        throw new InvalidDataException("Invalid format");
      }
    }

    private SignatureData getMachoSignatureData()
    {
      // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

      byte[] signedData = null;
      byte[] cmsData = null;
      using var reader = new BinaryReader(_stream, Encoding.UTF8, true);
      _stream.Seek(firstLoadCommandPosition, SeekOrigin.Begin); // load_command[0]
      var _ncmds = ncmds;

      while (_ncmds-- > 0)
      {
        var cmd = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmd
        var cmdsize = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmdsize

        if (cmd == MachoConsts.LC_CODE_SIGNATURE)
        {
          var dataoff = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::dataoff
          _stream.Seek(dataoff, SeekOrigin.Begin);

          var CS_SuperBlob_start = _stream.Position;
          _stream.Seek(8, SeekOrigin.Current);
          var CS_SuperBlob_count = ReadUtils.ReadUInt32Le(reader, true);

          while (CS_SuperBlob_count-- > 0)
          {
            var CS_BlobIndex_type = ReadUtils.ReadUInt32Le(reader, true);
            var CS_BlobIndex_offset = ReadUtils.ReadUInt32Le(reader, true);
            var position = _stream.Position;

            if (CS_BlobIndex_type == MachoConsts.CSSLOT_CODEDIRECTORY)
            {
              _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin);
              _stream.Seek(CS_BlobIndex_offset, SeekOrigin.Current);
              signedData = MachoUtils.ReadCodeDirectoryBlob(reader);
              _stream.Seek(position, SeekOrigin.Begin);
            }
            else if (CS_BlobIndex_type == MachoConsts.CSSLOT_CMS_SIGNATURE)
            {
              _stream.Seek(CS_SuperBlob_start, SeekOrigin.Begin);
              _stream.Seek(CS_BlobIndex_offset, SeekOrigin.Current);
              cmsData = MachoUtils.ReadBlob(reader);
              _stream.Seek(position, SeekOrigin.Begin);
            }
          }
        }

        _stream.Seek(cmdsize - 8, SeekOrigin.Current);
      }

      return new SignatureData(signedData, cmsData);
    }
  }
}