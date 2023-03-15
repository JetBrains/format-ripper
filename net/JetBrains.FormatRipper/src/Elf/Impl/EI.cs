using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class EI
  {
    internal const int EI_NIDENT = 16;

    // @formatter:off
    internal const int EI_MAG0       = 0; /* File identification byte 0 index */
    internal const int EI_MAG1       = 1; /* File identification byte 1 index */
    internal const int EI_MAG2       = 2; /* File identification byte 2 index */
    internal const int EI_MAG3       = 3; /* File identification byte 3 index */
    internal const int EI_CLASS      = 4; /* File class byte index */
    internal const int EI_DATA       = 5; /* Data encoding byte index */
    internal const int EI_VERSION    = 6; /* File version byte index */
    internal const int EI_OSABI      = 7; /* OS ABI identification */
    internal const int EI_ABIVERSION = 8; /* ABI version */
    internal const int EI_PAD        = 9; /* Byte index of padding bytes */
    // @formatter:on
  }
}