using System.Collections.Generic;
using System.IO;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Elf;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.FormatRipper.Sh;

namespace JetBrains.FormatRipper.FileExplorer
{
  public static class FileTypeExplorer
  {
    public static Result DetectFileType(Stream stream) =>
      TryParsePe(stream, out var properties) ? new Result(FileType.Pe, properties) :
      TryParseElf(stream, out properties) ? new Result(FileType.Elf, properties) :
      TryParseMachO(stream, out properties) ? new Result(FileType.MachO, properties) :
      TryParseMsi(stream, out properties) ? new Result(FileType.Msi, properties) :
      TryParseSh(stream, out properties) ? new Result(FileType.Sh, properties) : new Result(FileType.Unknown, FileProperties.UnknownType);

    public readonly struct Result
    {
      public Result(FileType fileType, FileProperties fileProperties)
      {
        FileType = fileType;
        FileProperties = fileProperties;
      }

      public readonly FileType FileType;
      public readonly FileProperties FileProperties;

      public void Deconstruct(out FileType fileType, out FileProperties fileProperties)
      {
        fileType = FileType;
        fileProperties = FileProperties;
      }
    }

    #region Impl

    private static bool TryParsePe(Stream stream, out FileProperties properties)
    {
      try
      {
        if (PeFile.Is(stream))
        {
          var file = PeFile.Parse(stream);
          properties = (file.Characteristics & (IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_DLL)) switch
            {
              IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE.IMAGE_FILE_DLL => FileProperties.SharedLibraryType,
              IMAGE_FILE.IMAGE_FILE_EXECUTABLE_IMAGE => FileProperties.ExecutableType,
              _ => FileProperties.UnknownType
            };
          if (file.HasSignature)
            properties |= FileProperties.Signed;
          if (file.HasMetadata)
            properties |= FileProperties.Managed;
          return true;
        }
      }
      catch (IOException)
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseElf(Stream stream, out FileProperties properties)
    {
      try
      {
        if (ElfFile.Is(stream))
        {
          var file = ElfFile.Parse(stream);
          properties = file.EType switch
            {
              ET.ET_EXEC => FileProperties.ExecutableType,
              ET.ET_DYN => file.Interpreter != null ? FileProperties.ExecutableType : FileProperties.SharedLibraryType,
              _ => FileProperties.UnknownType
            };
          return true;
        }
      }
      catch (IOException)
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseMachO(Stream stream, out FileProperties properties)
    {
      try
      {
        if (MachOFile.Is(stream))
        {
          static MH_FileType? GetAggregatedFileType(IEnumerable<MachOFile.Section> sections)
          {
            MH_FileType? fileType = null;
            foreach (var section in sections)
              if (fileType == null)
                fileType = section.MhFileType;
              else if (fileType != section.MhFileType)
                return null;

            return fileType;
          }

          static bool IsAllHasCodeSignature(IEnumerable<MachOFile.Section> sections)
          {
            foreach (var section in sections)
              if (!section.HasCodeSignature)
                return false;
            return true;
          }

          var file = MachOFile.Parse(stream);
          var fileSections = file.Sections;

          properties = GetAggregatedFileType(fileSections) switch
            {
              MH_FileType.MH_EXECUTE => FileProperties.ExecutableType,
              MH_FileType.MH_DYLIB => FileProperties.SharedLibraryType,
              MH_FileType.MH_BUNDLE => FileProperties.BundleType,
              _ => FileProperties.UnknownType
            };
          if (IsAllHasCodeSignature(fileSections))
            properties |= FileProperties.Signed;
          if (file.IsFatLittleEndian != null)
            properties |= FileProperties.MultiArch;
          return true;
        }
      }
      catch (IOException)
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseMsi(Stream stream, out FileProperties properties)
    {
      try
      {
        if (CompoundFile.Is(stream))
        {
          var file = CompoundFile.Parse(stream);
          if (file.Type == CompoundFile.FileType.Msi)
          {
            properties = file.HasSignature
              ? FileProperties.Signed
              : FileProperties.UnknownType;
            return true;
          }
        }
      }
      catch (IOException)
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseSh(Stream stream, out FileProperties properties)
    {
      try
      {
        if (ShFile.Is(stream))
        {
          properties = FileProperties.ExecutableType;
          return true;
        }
      }
      catch (IOException)
      {
      }

      properties = default;
      return false;
    }

    #endregion
  }
}