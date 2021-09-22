using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using JetBrains.Annotations;

namespace JetBrains.SignatureVerifier.Macho
{
    /// <summary>
    /// Fat/Universal Mach-O file
    /// </summary>
    public class MachoArch
    {
        private readonly Stream _stream;
        private readonly ILogger _logger;

        /// <summary>
        ///Initializes a new instance of the  <see cref="T:JetBrains.SignatureVerifier.MachoArch"></see> 
        /// </summary>
        /// <param name="stream">An input stream</param>
        /// <param name="logger">A logger</param>
        /// <exception cref="PlatformNotSupportedException">Indicates the byte order ("endianness")
        /// in which data is stored in this computer architecture is not Little Endian.</exception>
        public MachoArch([NotNull] Stream stream, ILogger logger)
        {
            if (!BitConverter.IsLittleEndian)
                throw new PlatformNotSupportedException("Only Little endian is expected");

            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _logger = logger ?? NullLogger.Instance;
        }

        /// <summary>
        /// Return a list of macho architectures from fat-macho or one-item list for macho 
        /// </summary>
        /// <returns>A collection of MachoFile</returns>
        public ReadOnlyCollection<MachoFile> Extract()
        {
            using var reader = new BinaryReader(_stream.Rewind(), Encoding.UTF8, true);
            var masterMagic = reader.ReadUInt32(); // mach_header::magic / mach_header64::magic / fat_header::magic

            if (MachoUtils.IsMacho(masterMagic))
                return new List<MachoFile> { getMachoData(_stream.Rewind()) }.AsReadOnly();
            else if (MachoUtils.IsFatMacho(masterMagic))
                return getFatMachoData(reader, masterMagic);
            else
                throw new InvalidDataException("Unknown format");
        }

        private ReadOnlyCollection<MachoFile> getFatMachoData(BinaryReader reader, uint magic)
        {
            var isLe32 = magic == MachoConsts.FAT_MAGIC;
            var isLe64 = magic == MachoConsts.FAT_MAGIC_64;
            var isBe32 = magic == MachoConsts.FAT_CIGAM;
            var isBe64 = magic == MachoConsts.FAT_CIGAM_64;

            if (isLe32 || isLe64 || isBe32 || isBe64)
            {
                var nFatArch = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // fat_header::nfat_arch
                var fatArchItems = new List<DataInfo>();

                if (isBe64 || isLe64)
                    while (nFatArch-- > 0)
                    {
                        _stream.Seek(8, SeekOrigin.Current);
                        fatArchItems.Add(new DataInfo(
                            (int)ReadUtils.ReadUInt64Le(reader, isBe64), //fat_arch_64::offset
                            (int)ReadUtils.ReadUInt64Le(reader, isBe64))); //fat_arch_64::size
                        _stream.Seek(8, SeekOrigin.Current);
                    }
                else
                    while (nFatArch-- > 0)
                    {
                        _stream.Seek(8, SeekOrigin.Current);
                        fatArchItems.Add(new DataInfo(
                            (int)ReadUtils.ReadUInt32Le(reader, isBe32), //fat_arch::offset
                            (int)ReadUtils.ReadUInt32Le(reader, isBe32))); //fat_arch::size
                        _stream.Seek(4, SeekOrigin.Current);
                    }

                return fatArchItems.Select(
                        s =>
                        {
                            _stream.Seek(s.Offset, SeekOrigin.Begin);
                            return new MachoFile(reader.ReadBytes(s.Size), _logger);
                        })
                    .ToList()
                    .AsReadOnly();
            }

            throw new InvalidDataException("Unknown format");
        }

        private MachoFile getMachoData(Stream stream)
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return new MachoFile(ms.ToArray(), _logger);
        }
    }
}