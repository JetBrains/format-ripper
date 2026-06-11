using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [Flags]
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum SHF : uint
  {
    // @formatter:off
    SHF_WRITE            = 0x00000001, // Writable
    SHF_ALLOC            = 0x00000002, // Occupies memory during execution
    SHF_EXECINSTR        = 0x00000004, // Executable
    SHF_MERGE            = 0x00000010, // Might be merged
    SHF_STRINGS          = 0x00000020, // Contains nul-terminated strings
    SHF_INFO_LINK        = 0x00000040, // sh_info contains SHT index
    SHF_LINK_ORDER       = 0x00000080, // Preserve order after combining
    SHF_OS_NONCONFORMING = 0x00000100, // Non-standard OS specific handling required
    SHF_GROUP            = 0x00000200, // Section is member of a group
    SHF_TLS              = 0x00000400, // Section holds thread-local data
    SHF_COMPRESSED       = 0x00000800, // Section with compressed data
    SHF_GNU_RETAIN       = 0x00200000, // Not to be garbage collected by linker
    SHF_MIPS_NOSTRIP     = 0x08000000, // MIPS: section data may not be stripped
    SHF_IA_64_SHORT      = 0x10000000, // IA-64: section near gp (short, gp-relative addressing)
    SHF_ORDERED          = 0x40000000, // Special ordering requirement (Solaris)
    SHF_EXCLUDE          = 0x80000000, // Section is excluded unless referenced or allocated (Solaris)
    SHF_MASKOS           = 0x0ff00000, // OS-specific
    SHF_MASKPROC         = 0xf0000000  // Processor-specific
    // @formatter:on
  }
}
