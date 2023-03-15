using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal enum PT : uint
  {
    // @formatter:off
    PT_NULL         =          0, // Program header table entry unused
    PT_LOAD         =          1, // Loadable program segment
    PT_DYNAMIC      =          2, // Dynamic linking information
    PT_INTERP       =          3, // Program interpreter
    PT_NOTE         =          4, // Auxiliary information
    PT_SHLIB        =          5, // Reserved
    PT_PHDR         =          6, // Entry for header table itself
    PT_TLS          =          7, // Thread-local storage segment
    PT_NUM          =          8, // Number of defined types
    PT_LOOS         = 0x60000000, // Start of OS-specific
    PT_GNU_EH_FRAME = 0x6474e550, // GCC .eh_frame_hdr segment
    PT_GNU_STACK    = 0x6474e551, // Indicates stack executability
    PT_GNU_RELRO    = 0x6474e552, // Read-only after relocation
    PT_LOSUNW       = 0x6ffffffa,
    PT_SUNWBSS      = 0x6ffffffa, // Sun Specific segment
    PT_SUNWSTACK    = 0x6ffffffb, // Stack segment
    PT_HISUNW       = 0x6fffffff,
    PT_HIOS         = 0x6fffffff, // End of OS-specific
    PT_LOPROC       = 0x70000000, // Start of processor-specific
    PT_HIPROC       = 0x7fffffff // End of processor-specific
    // @formatter:on
  }
}