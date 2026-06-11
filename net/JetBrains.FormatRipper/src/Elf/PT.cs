using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum PT : uint
  {
    // @formatter:off
    PT_NULL                =          0, // Program header table entry unused
    PT_LOAD                =          1, // Loadable program segment
    PT_DYNAMIC             =          2, // Dynamic linking information
    PT_INTERP              =          3, // Program interpreter
    PT_NOTE                =          4, // Auxiliary information
    PT_SHLIB               =          5, // Reserved
    PT_PHDR                =          6, // Entry for header table itself
    PT_TLS                 =          7, // Thread-local storage segment
    PT_NUM                 =          8, // Number of defined types

    PT_LOOS                = 0x60000000, // Start of OS-specific
    PT_GNU_EH_FRAME        = 0x6474e550, // GCC .eh_frame_hdr segment
    PT_GNU_STACK           = 0x6474e551, // Indicates stack executability
    PT_GNU_RELRO           = 0x6474e552, // Read-only after relocation
    PT_GNU_PROPERTY        = 0x6474e553, // GNU property
    PT_GNU_SFRAME          = 0x6474e554, // SFrame segment

    // OpenBSD-specific
    PT_OPENBSD_MUTABLE     = 0x65a3dbe5, // Like bss, but not immutable
    PT_OPENBSD_RANDOMIZE   = 0x65a3dbe6, // Fill with random data
    PT_OPENBSD_WXNEEDED    = 0x65a3dbe7, // Program performs W^X violations
    PT_OPENBSD_NOBTCFI     = 0x65a3dbe8, // Do not enforce branch target CFI
    PT_OPENBSD_SYSCALLS    = 0x65a3dbe9, // System call sites
    PT_OPENBSD_BOOTDATA    = 0x65a41be6, // Section for boot arguments

    PT_LOSUNW              = 0x6ffffffa,
    PT_SUNWBSS             = 0x6ffffffa, // Sun Specific segment
    PT_SUNWSTACK           = 0x6ffffffb, // Stack segment
    PT_HISUNW              = 0x6fffffff,
    PT_HIOS                = 0x6fffffff, // End of OS-specific

    PT_LOPROC              = 0x70000000, // Start of processor-specific

    // ARM-specific
    PT_ARM_ARCHEXT         = 0x70000000, // Platform architecture compatibility info
    PT_ARM_EXIDX           = 0x70000001, // Stack unwinding tables
    PT_ARM_UNWIND          = 0x70000001, // Stack unwinding tables (alias for PT_ARM_EXIDX)

    // AArch64-specific
    PT_AARCH64_MEMTAG_MTE  = 0x70000002, // Memory tagging extension segment

    // MIPS-specific
    PT_MIPS_REGINFO        = 0x70000000, // Register usage information
    PT_MIPS_RTPROC         = 0x70000001, // Runtime procedure table
    PT_MIPS_OPTIONS        = 0x70000002, // Options segment
    PT_MIPS_ABIFLAGS       = 0x70000003, // FP mode requirement

    // RISC-V-specific
    PT_RISCV_ATTRIBUTES    = 0x70000003, // Attribute information

    PT_HIPROC              = 0x7fffffff  // End of processor-specific
    // @formatter:on
  }
}