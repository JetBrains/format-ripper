using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum ET : ushort
  {
    // @formatter:off
    ET_NONE   =      0, // Unknown type
    ET_REL    =      1, // Relocatable
    ET_EXEC   =      2, // Executable
    ET_DYN    =      3, // Shared object
    ET_CORE   =      4, // Core file
    ET_LOOS   = 0xfe00, // First operating system specific
    ET_HIOS   = 0xfeff, // Last operating system-specific
    ET_LOPROC = 0xff00, // First processor-specific
    ET_HIPROC = 0xffff  // Last processor-specific
    // @formatter:on
  }
}