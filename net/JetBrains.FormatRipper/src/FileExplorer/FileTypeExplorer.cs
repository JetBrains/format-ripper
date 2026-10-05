using System;
using System.Collections.Generic;
using System.IO;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Elf;
using JetBrains.FormatRipper.MachO;
using JetBrains.FormatRipper.Pe;
using JetBrains.FormatRipper.Sh;

namespace JetBrains.FormatRipper.FileExplorer
{
  public static class FileTypeExplorer
  {
    public static Result Detect(Stream stream) => new(
      TryParsePe(stream, out var properties) ? FileType.Pe :
      TryParseElf(stream, out properties) ? FileType.Elf :
      TryParseMachO(stream, out properties) ? FileType.MachO :
      TryParseMsi(stream, out properties) ? FileType.Msi :
      TryParseSh(stream, out properties) ? FileType.Sh :
      TryParseDmg(stream, out properties) ? FileType.Dmg :
      FileType.Unknown, properties);

#if !(NET20 || NET30)
    public static Result DetectFileType(this Stream stream) => Detect(stream);
#endif

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
      catch
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseElf(Stream stream, out FileProperties properties)
    {
      try
      {
        var file = ElfFile.Parse(stream);
        properties = file.EType switch
          {
            ET.ET_EXEC => FileProperties.ExecutableType,
            ET.ET_DYN => ElfUtil.HasInterp(file.Programs) ? FileProperties.ExecutableType : FileProperties.SharedLibraryType,
            ET.ET_REL => FileProperties.RelocatableType,
            ET.ET_CORE => FileProperties.CoreDumpType,
            _ => FileProperties.UnknownType
          };
        return true;
      }
      catch
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseMachO(Stream stream, out FileProperties properties)
    {
      try
      {
        static MH_FileType? GetAggregatedFileType(IEnumerable<MachOFile.Image> images)
        {
          MH_FileType? fileType = null;
          foreach (var image in images)
            if (fileType == null)
              fileType = image.MhFileType;
            else if (fileType != image.MhFileType)
              return null;

          return fileType;
        }

        bool IsAllHasCodeSignature(IEnumerable<MachOFile.Image> images)
        {
          foreach (var image in images)
            if (!MachOUtil.ReadLoadCommands(image).HasSignature)
              return false;
          return true;
        }

        var file = MachOFile.Parse(stream);
        var fileImages = file.Images;

        properties = GetAggregatedFileType(fileImages) switch
          {
            MH_FileType.MH_EXECUTE => FileProperties.ExecutableType,
            MH_FileType.MH_DYLIB => FileProperties.SharedLibraryType,
            MH_FileType.MH_BUNDLE => FileProperties.BundleType,
            _ => FileProperties.UnknownType
          };
        if (IsAllHasCodeSignature(fileImages))
          properties |= FileProperties.Signed;
        if (file.FatEndian != null)
          properties |= FileProperties.MultiArch;
        return true;
      }
      catch
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseMsi(Stream stream, out FileProperties properties)
    {
      try
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
      catch
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseSh(Stream stream, out FileProperties properties)
    {
      try
      {
        var file = ShFile.Parse(stream);
        properties = FileProperties.ExecutableType;
        return true;
      }
      catch
      {
      }

      properties = default;
      return false;
    }

    private static bool TryParseDmg(Stream stream, out FileProperties properties)
    {
      try
      {
        var file = DmgFile.Parse(stream);
        properties = FileProperties.BundleType;
        if (file.HasSignature)
          properties |= FileProperties.Signed;
        return true;
      }
      catch
      {
      }

      properties = default;
      return false;
    }

    #endregion
  }
}