using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum SHN : ushort
  {
    // @formatter:off
    SHN_UNDEF     = 0x0000, // Undefined, missing, irrelevant, or otherwise meaningless section reference
    SHN_LORESERVE = 0xff00, // Start of reserved indices
    SHN_LOPROC    = 0xff00, // Start of processor-specific
    SHN_HIPROC    = 0xff1f, // End of processor-specific
    SHN_LOOS      = 0xff20, // Start of OS-specific
    SHN_HIOS      = 0xff3f, // End of OS-specific
    SHN_ABS       = 0xfff1, // Associated symbol is absolute and not affected by relocation
    SHN_COMMON    = 0xfff2, // Associated symbol is a common (not yet allocated) block
    SHN_XINDEX    = 0xffff, // Real section index is in the SHT_SYMTAB_SHNDX extra table
    SHN_HIRESERVE = 0xffff  // End of reserved indices
    // @formatter:on
  }
}