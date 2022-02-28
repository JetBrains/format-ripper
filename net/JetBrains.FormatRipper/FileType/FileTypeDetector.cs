using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using JetBrains.Annotations;
using JetBrains.SignatureVerifier;

namespace JetBrains.Util.FileType
{
  public static class FileTypeDetector
  {
    public static (FileType FileType, FileProperties FileProperties) DetectFileType([NotNull] this Stream stream)
    {
      if (stream == null)
        throw new ArgumentNullException(nameof(stream));
      FileProperties? res;
      if ((res = IsPe(stream)) != null)
        return (FileType.Pe, res.Value);
      if ((res = IsMsi(stream)) != null)
        return (FileType.Msi, res.Value);
      if ((res = TryParseMachO(stream, out _)) != null)
        return (FileType.MachO, res.Value);
      if ((res = IsElf(stream)) != null)
        return (FileType.Elf, res.Value);
      if ((res = IsShebangScript(stream)) != null)
        return (FileType.ShebangScript, res.Value);
      return (FileType.Unknown, FileProperties.UnknownType);
    }

    #region Impl

    private static FileProperties? IsPe([NotNull] Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");
      try
      {
        using (var reader = new BinaryReader(stream.Rewind(), Encoding.UTF8, true))
        {
          if (reader.ReadUInt16() != 0x5A4D) // IMAGE_DOS_SIGNATURE
            return null;
          stream.Seek(0x3C, SeekOrigin.Begin); // IMAGE_DOS_HEADER::e_lfanew
          stream.Seek(reader.ReadUInt32(), SeekOrigin.Begin);
          if (reader.ReadUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
            return null;
          stream.Seek(0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics
          var fileProperties = (reader.ReadUInt16() & 0x2002) switch
          {
            0x2002 => FileProperties.SharedLibraryType, // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
            0x0002 => FileProperties.ExecutableType, // IMAGE_FILE_EXECUTABLE_IMAGE
            _ => FileProperties.UnknownType
          };
          switch (reader.ReadUInt16()) // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
          {
          case 0x10b: // IMAGE_NT_OPTIONAL_HDR32_MAGIC
            stream.Seek(0x60 - sizeof(ushort), SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
            break;
          case 0x20b: // IMAGE_NT_OPTIONAL_HDR64_MAGIC
            stream.Seek(0x70 - sizeof(ushort), SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
            break;
          default:
            return null;
          }

          stream.Seek(sizeof(ulong) * 4, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
          var securityRva = reader.ReadUInt32();
          var securitySize = reader.ReadUInt32();
          if (securityRva != 0 && securitySize != 0)
            fileProperties |= FileProperties.Signed;

          stream.Seek(sizeof(ulong) * 9, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
          var comRva = reader.ReadUInt32();
          var comSize = reader.ReadUInt32();
          if (comRva != 0 && comSize != 0)
            fileProperties |= FileProperties.Managed;

          return fileProperties;
        }
      }
      catch (EndOfStreamException)
      {
        return null;
      }
    }

    private static FileProperties? IsMsi([NotNull] Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");
      // Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft
      try
      {
        using (var reader = new BinaryReader(stream.Rewind(), Encoding.UTF8, true))
        {
          if (reader.ReadUInt64() != 0xE11AB1A1E011CFD0)
            return null;
          return FileProperties.UnknownType;
        }
      }
      catch (EndOfStreamException)
      {
        return null;
      }
    }

    private static FileProperties? IsElf([NotNull] Stream stream)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");
      try
      {
        using (var reader = new BinaryReader(stream.Rewind(), Encoding.UTF8, true))
        {
          // Note: See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

          if (reader.ReadUInt32() != 0x464C457F) // e_ident[EI_MAG0..EI_MAG3]
            return null;

          bool is64;
          switch (reader.ReadByte()) // e_ident[EI_CLASS]
          {
          case 1:
            is64 = false;
            break;
          case 2:
            is64 = true;
            break;
          default: return null;
          }

          bool isBe;
          switch (reader.ReadByte()) // e_ident[EI_DATA]
          {
          case 1:
            isBe = false;
            break;
          case 2:
            isBe = true;
            break;
          default: return null;
          }

          if (reader.ReadByte() != 1) // e_ident[EI_VERSION]
            return null;
          stream.Seek(9, SeekOrigin.Current);
          var eType = ReadUtils.ReadUInt16Le(reader, isBe); // e_type
          stream.Seek(2, SeekOrigin.Current);
          if (ReadUtils.ReadUInt32Le(reader, isBe) != 1) // e_version
            return null;

          switch (eType)
          {
          case 0x02: return FileProperties.ExecutableType; // ET_EXEC
          case 0x03: break; // ET_DYN
          default: return FileProperties.UnknownType;
          }

          stream.Seek(is64 ? 8 : 4, SeekOrigin.Current);
          var ePhOff = is64 ? ReadUtils.ReadUInt64Le(reader, isBe) : ReadUtils.ReadUInt32Le(reader, isBe); // e_phoff

          stream.Seek(is64 ? 0x10 : 0xC, SeekOrigin.Current);
          var ePhNum = ReadUtils.ReadUInt16Le(reader, isBe); // e_phnum

          stream.Seek(checked((long)ePhOff), SeekOrigin.Begin);
          var hasExecutable = false;
          while (ePhNum-- > 0)
          {
            if (ReadUtils.ReadUInt32Le(reader, isBe) == 0x00000003) // PT_INTERP
              hasExecutable = true;
            stream.Seek(is64 ? 0x34 : 0x1C, SeekOrigin.Current);
          }

          return hasExecutable ? FileProperties.ExecutableType : FileProperties.SharedLibraryType;
        }
      }
      catch (EndOfStreamException)
      {
        return null;
      }
    }

    public static FileProperties? TryParseMachO([NotNull] Stream stream, out ProcessorArchitecture[] fileArchitectures)
    {
      if (!BitConverter.IsLittleEndian)
        throw new PlatformNotSupportedException("Only Little endian is expected");
      try
      {
        using (var reader = new BinaryReader(stream.Rewind(), Encoding.UTF8, true))
        {
          FileProperties? ReadHeader(uint magic, out ProcessorArchitecture[] fileArchitecture)
          {
            // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

            var isLe32 = magic == 0xFEEDFACE; // MH_MAGIC
            var isLe64 = magic == 0xFEEDFACF; // MH_MAGIC_64
            var isBe32 = magic == 0xCEFAEDFE; // MH_CIGAM
            var isBe64 = magic == 0xCFFAEDFE; // MH_CIGAM_64
            if (isLe32 || isLe64 || isBe32 || isBe64)
            {
              // Machine types:
              const uint CPU_ARCH_ABI64 = 0x01000000;
              const uint CPU_TYPE_X86 = 7;
              const uint CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
              const uint CPU_TYPE_ARM64 = 12 | CPU_ARCH_ABI64;
              var cputype = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64) switch // mach_header::cputype / mach_header_64::cputype
              {
                CPU_TYPE_X86 => ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL, // CPU_TYPE_X86
                CPU_TYPE_X86_64 => ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64, // CPU_TYPE_X86_64
                CPU_TYPE_ARM64 => ProcessorArchitecture.PROCESSOR_ARCHITECTURE_ARM64, // CPU_TYPE_ARM64
                _ => ProcessorArchitecture.PROCESSOR_ARCHITECTURE_UNKNOWN
              };

              stream.Seek(4, SeekOrigin.Current);
              var fileProperties = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64) switch // mach_header::filetype / mach_header_64::filetype
              {
                0x2 => FileProperties.ExecutableType, // MH_EXECUTE
                0x6 => FileProperties.SharedLibraryType, // MH_DYLIB
                0x8 => FileProperties.BundleType, // MH_BUNDLE
                _ => FileProperties.UnknownType
              };
              var ncmds = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // mach_header::ncmds / mach_header_64::ncmds
              stream.Seek(isLe64 || isBe64 ? 0xC : 0x8, SeekOrigin.Current); // load_command[0]
              while (ncmds-- > 0)
              {
                var cmd = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmd
                var cmdsize = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // load_command::cmdsize
                stream.Seek(cmdsize - 8, SeekOrigin.Current);

                if (cmd == 0x1D) // LC_CODE_SIGNATURE
                  fileProperties |= FileProperties.Signed;
              }

              fileArchitecture = new[] { cputype };
              return fileProperties;
            }

            fileArchitecture = null;
            return null;
          }

          FileProperties? ReadFatHeader(uint magic, out ProcessorArchitecture[] fileArchitectures)
          {
            // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h

            var isLe32 = magic == 0xCAFEBABE; // FAT_MAGIC
            var isLe64 = magic == 0xCAFEBABF; // FAT_MAGIC_64
            var isBe32 = magic == 0xBEBAFECA; // FAT_CIGAM
            var isBe64 = magic == 0xBFBAFECA; // FAT_CIGAM_64
            if (isLe32 || isLe64 || isBe32 || isBe64)
            {
              fileArchitectures = null; // none if error
              var nFatArch = ReadUtils.ReadUInt32Le(reader, isBe32 || isBe64); // fat_header ::nfat_arch

              var offsets = new List<ulong>();
              if (isBe64 || isLe64)
                while (nFatArch-- > 0)
                {
                  stream.Seek(8, SeekOrigin.Current);
                  offsets.Add(ReadUtils.ReadUInt64Le(reader, isBe64)); // fat_arch_64::offset
                  stream.Seek(16, SeekOrigin.Current);
                }
              else
                while (nFatArch-- > 0)
                {
                  stream.Seek(8, SeekOrigin.Current);
                  offsets.Add(ReadUtils.ReadUInt32Le(reader, isBe32)); // fat_arch::offset
                  stream.Seek(8, SeekOrigin.Current);
                }

              var fileArchitecturesList = new List<ProcessorArchitecture>();
              var filePropertiesList = offsets.Select(offset =>
              {
                stream.Seek(checked((long)offset), SeekOrigin.Begin);
                var fileProperties = ReadHeader(reader.ReadUInt32(), out var fileArchitecture); // mach_header::magic / mach_header64::magic
                if (fileProperties != null) fileArchitecturesList.Add(fileArchitecture[0]);
                return fileProperties;
              }).ToList();
              if (filePropertiesList.Count == 0)
                return FileProperties.UnknownType;

              // One of headers is invalid
              if (filePropertiesList.Any(x => x == null))
                return null;

              // Headers are incompatible
              if (filePropertiesList.Distinct().Count() > 1)
                return null;

              var totalFileProperty = filePropertiesList[0];
              if (filePropertiesList.Count > 1)
                totalFileProperty |= FileProperties.MultiArch;

              fileArchitectures = fileArchitecturesList.ToArray();
              return totalFileProperty;
            }

            fileArchitectures = null;
            return null;
          }

          var masterMagic = reader.ReadUInt32(); // mach_header::magic / mach_header64::magic / fat_header::magic
          return ReadFatHeader(masterMagic, out fileArchitectures) ?? ReadHeader(masterMagic, out fileArchitectures);
        }
      }
      catch (EndOfStreamException)
      {
        fileArchitectures = null;
        return null;
      }
    }


    private static FileProperties? IsShebangScript([NotNull] Stream stream)
    {
      try
      {
        using (var reader = new BinaryReader(stream.Rewind(), Encoding.UTF8, true))
        {
          if (reader.ReadByte() == '#' && reader.ReadByte() == '!')
          {
            var c = reader.ReadByte();
            while (c == ' ' || c == '\t')
              c = reader.ReadByte();
            if (c == '/')
              return FileProperties.ExecutableType;
          }
          return null;
        }
      }
      catch (EndOfStreamException)
      {
        return null;
      }
    }

    #endregion
  }
}