using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum ELFCLASS : byte
  {
    // @formatter:off
    ELFCLASSNONE = 0,
    ELFCLASS32   = 1, // 32-bit object file
    ELFCLASS64   = 2  // 64-bit object file
    // @formatter:on
  }
}