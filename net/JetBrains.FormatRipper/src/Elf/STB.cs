using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum STB : byte
  {
    // @formatter:off
    STB_LOCAL  =  0, // Not visible outside the object file
    STB_GLOBAL =  1, // Visible to all object files being combined
    STB_WEAK   =  2, // Like global, but with lower-precedence definition
    STB_LOOS   = 10, // Start of OS-specific binding
    STB_HIOS   = 12, // End of OS-specific binding
    STB_LOPROC = 13, // Start of processor-specific binding
    STB_HIPROC = 15  // End of processor-specific binding
    // @formatter:on
  }
}
