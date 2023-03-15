using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  internal enum MH : uint
  {
    // @formatter:off
    FAT_MAGIC    = 0xCAFEBABE,
    FAT_MAGIC_64 = 0xCAFEBABF,
    FAT_CIGAM    = 0xBEBAFECA,
    FAT_CIGAM_64 = 0xBFBAFECA,
    // @formatter:on

    // @formatter:off
    MH_MAGIC    = 0xFEEDFACE,
    MH_MAGIC_64 = 0xFEEDFACF,
    MH_CIGAM    = 0xCEFAEDFE,
    MH_CIGAM_64 = 0xCFFAEDFE
    // @formatter:on
  }
}