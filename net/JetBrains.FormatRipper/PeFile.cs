﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using JetBrains.Annotations;
using JetBrains.Util;

namespace JetBrains.SignatureVerifier
{
  /// <summary>
  ///Portable Executable file
  /// </summary>
  public class PeFile
  {
    private readonly Stream _stream;
    private readonly DataInfo _checkSum;
    private readonly DataInfo _imageDirectoryEntrySecurity;
    private readonly DataInfo _signData;
    private readonly DataInfo _dotnetMetadata;

    private byte[] _rawPeData;
    private byte[] RawPeData => _rawPeData ??= _stream.ReadAll();

    public int ImageDirectoryEntrySecurityOffset => _imageDirectoryEntrySecurity.Offset;

    /// <summary>
    /// PE is .NET assembly
    /// </summary>
    public bool IsDotNet => !_dotnetMetadata.IsEmpty;

    ///  <summary>
    /// Initializes a new instance of the  <see cref="T:JetBrains.SignatureVerifier.PeFile"></see>
    ///  </summary>
    ///  <param name="stream">An input stream</param>
    ///  <exception cref="PlatformNotSupportedException">Indicates the byte order ("endianness")
    ///  in which data is stored in this computer architecture is not Little Endian.</exception>
    ///  <exception cref="InvalidDataException">Indicates the data in the input stream does not correspond to PE-format.</exception>
    public PeFile([NotNull] Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");

      _stream = stream ?? throw new ArgumentNullException(nameof(stream));
      _stream.Rewind();
      using var reader = new BinaryReader(stream, Encoding.UTF8, true);

      if (reader.ReadUInt16() != 0x5A4D) // IMAGE_DOS_SIGNATURE
        throw new InvalidDataException("Unknown format");

      stream.Seek(0x3C, SeekOrigin.Begin); // IMAGE_DOS_HEADER::e_lfanew
      var ntHeaderOffset = reader.ReadUInt32();
      stream.Seek(ntHeaderOffset, SeekOrigin.Begin);
      _checkSum = new DataInfo((int)(ntHeaderOffset + 0x58), 4);

      if (reader.ReadUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
        throw new InvalidDataException("Unknown format");

      stream.Seek(0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics

      var characteristics = reader.ReadUInt16() & 0x2002;

      //IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
      if (characteristics != 0x2002 && characteristics != 0x0002)
        throw new InvalidDataException("Unknown format");

      switch (reader.ReadUInt16()) // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
      {
        case 0x10b: // IMAGE_NT_OPTIONAL_HDR32_MAGIC
          stream.Seek(0x60 - sizeof(ushort),
            SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
          break;
        case 0x20b: // IMAGE_NT_OPTIONAL_HDR64_MAGIC
          stream.Seek(0x70 - sizeof(ushort),
            SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
          break;
        default:
          throw new InvalidDataException("Unknown format");
      }

      stream.Seek(sizeof(ulong) * 4, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
      _imageDirectoryEntrySecurity = new DataInfo((int)stream.Position, 8);
      var securityRva = reader.ReadUInt32();
      var securitySize = reader.ReadUInt32();
      _signData = new DataInfo((int)securityRva, (int)securitySize);

      stream.Seek(sizeof(ulong) * 9L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
      var dotnetMetadataRva = reader.ReadUInt32();
      var dotnetMetadataSize = reader.ReadUInt32();
      _dotnetMetadata = new DataInfo((int)dotnetMetadataRva, (int)dotnetMetadataSize);
    }

    /// <summary>
    /// Retrieve the signature data from PE
    /// </summary>
    public SignatureData GetSignatureData()
    {
      if (_signData.IsEmpty)
        return SignatureData.Empty;

      if (!_stream.CanRead || !_stream.CanSeek)
        return SignatureData.Empty;

      try
      {
        using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);
        //jump to the sign data
        _stream.Seek(_signData.Offset, SeekOrigin.Begin);
        var dwLength = reader.ReadInt32();

        //skip wRevision, wCertificateType
        _stream.Seek(4, SeekOrigin.Current);

        var res = reader.ReadBytes(_signData.Size);

        //need more data
        if (res.Length < dwLength - 8)
          return SignatureData.Empty;

        return new SignatureData(null, res);
      }
      catch (EndOfStreamException)
      {
        //need more data
        return SignatureData.Empty;
      }
    }

    /// <summary>
    /// Compute hash of PE structure
    /// </summary>
    /// <param name="algName">Name of the hashing algorithm</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">if algName is null</exception>
    public byte[] ComputeHash([NotNull] string algName)
    {
      if (algName == null) throw new ArgumentNullException(nameof(algName));

      var data = RawPeData;
      using var hash = IncrementalHash.CreateHash(new HashAlgorithmName(algName.ToUpper()));

      //hash from start to checksum field
      int offset = 0;
      int count = _checkSum.Offset;
      hash.AppendData(data, offset, count);

      //jump over checksum and hash to IMAGE_DIRECTORY_ENTRY_SECURITY
      offset = count + _checkSum.Size;
      count = _imageDirectoryEntrySecurity.Offset - offset;
      hash.AppendData(data, offset, count);

      //jump over IMAGE_DIRECTORY_ENTRY_SECURITY
      offset = _imageDirectoryEntrySecurity.Offset + _imageDirectoryEntrySecurity.Size;

      if (_signData.IsEmpty) // PE is not signed
      {
        //hash to EOF
        count = data.Length - offset;
        hash.AppendData(data, offset, count);
      }
      else
      {
        //PE is signed
        count = _signData.Offset - offset;

        //hash to start the signature data
        if ((offset + count) <= data.Length)
          hash.AppendData(data, offset, count);

        //jump over the signature data and hash all the rest
        offset = _signData.Offset + _signData.Size;
        count = data.Length - offset;

        if (count > 0)
          hash.AppendData(data, offset, count);
      }

      return hash.GetHashAndReset();
    }
  }
}