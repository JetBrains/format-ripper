using System;
using System.IO;
using System.Text;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Macho
{
  public class MachoFile
  {
    private readonly Stream _stream;
    public uint Magic { get; private set; }

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
    }

    public byte[] ComputeHash(string algName)
    {
      throw new NotImplementedException();
    }

    /// <summary>
    /// Retrieve the signature data from MachO
    /// </summary>
    /// <exception cref="InvalidDataException">Indicates the data in the input stream does not correspond to MachO format or the signature data is malformed</exception>
    [NotNull]
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
      var isLe32 = Magic == MachoConsts.MH_MAGIC;
      var isLe64 = Magic == MachoConsts.MH_MAGIC_64;
      var isBe32 = Magic == MachoConsts.MH_CIGAM;
      var isBe64 = Magic == MachoConsts.MH_CIGAM_64;

      if (isLe32 || isLe64 || isBe32 || isBe64)
      {
        using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);
        _stream.Seek(16, SeekOrigin.Current);
        var ncmds = ReadUtils.ReadUInt32Le(reader,
          isBe32 || isBe64); // mach_header::ncmds / mach_header_64::ncmds
        _stream.Seek(isLe64 || isBe64 ? 0xC : 0x8, SeekOrigin.Current); // load_command[0]

        while (ncmds-- > 0)
        {
          var cmd = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmd
          var cmdsize = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmdsize

          if (cmd == 0x1D) // LC_CODE_SIGNATURE
          {
            var dataoff = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::dataoff
            _stream.Rewind();
            _stream.Seek(dataoff, SeekOrigin.Current);

            var CS_SuperBlob_start = _stream.Position;
            var CS_SuperBlob_magic = ReadUtils.ReadUInt32Le(reader, true);
            var CS_SuperBlob_length = ReadUtils.ReadUInt32Le(reader, true);
            var CS_SuperBlob_count = ReadUtils.ReadUInt32Le(reader, true);

            for (int i = 0; i < CS_SuperBlob_count; i++)
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

      throw new InvalidDataException("Unknown format");
    }
  }
}