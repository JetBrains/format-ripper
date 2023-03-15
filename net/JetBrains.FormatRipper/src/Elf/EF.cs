using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum EF : uint
  {
    // @formatter:off

    EF_ARM_RELEXEC          = 0x00000001,
    EF_ARM_HASENTRY         = 0x00000002,
    EF_ARM_SYMSARESORTED    = 0x00000004,
    EF_ARM_DYNSYMSUSESEGIDX = 0x00000008,
    EF_ARM_MAPSYMSFIRST     = 0x00000010,
    EF_ARM_LE8              = 0x00400000,
    EF_ARM_BE8              = 0x00800000,
    EF_ARM_EABIMASK         = 0xFF000000,
    EF_ARM_EABI_UNKNOWN     = 0x00000000,
    EF_ARM_EABI_VER1        = 0x01000000,
    EF_ARM_EABI_VER2        = 0x02000000,
    EF_ARM_EABI_VER3        = 0x03000000,
    EF_ARM_EABI_VER4        = 0x04000000,
    EF_ARM_EABI_VER5        = 0x05000000,
    EF_ARM_INTERWORK        = 0x00000004,
    EF_ARM_APCS_26          = 0x00000008,
    EF_ARM_APCS_FLOAT       = 0x00000010,
    EF_ARM_PIC              = 0x00000020,
    EF_ARM_ALIGN8           = 0x00000040,
    EF_ARM_NEW_ABI          = 0x00000080,
    EF_ARM_OLD_ABI          = 0x00000100,
    EF_ARM_ABI_FLOAT_SOFT   = 0x00000200,
    EF_ARM_ABI_FLOAT_HARD   = 0x00000400,
    EF_ARM_MAVERICK_FLOAT   = 0x00000800,

    EF_MIPS_NOREORDER     = 0x00000001,
    EF_MIPS_PIC           = 0x00000002, // Contains PIC code
    EF_MIPS_CPIC          = 0x00000004, // STD PIC calling sequence
    EF_MIPS_UCODE         = 0x00000010,
    EF_MIPS_ABI2          = 0x00000020, // N32
    EF_MIPS_OPTIONS_FIRST = 0x00000080,
    EF_MIPS_32BITMODE     = 0x00000100,
    EF_MIPS_ABI           = 0x0000F000,
    EF_MIPS_ABI_O32       = 0x00001000,
    EF_MIPS_ABI_O64       = 0x00002000,
    EF_MIPS_ABI_EABI32    = 0x00003000,
    EF_MIPS_ABI_EABI64    = 0x00004000,
    EF_MIPS_ARCH_ASE      = 0x0F000000, // Architectural extensions
    EF_MIPS_ARCH_ASE_MDMX = 0x08000000, // MDMX multimedia extension
    EF_MIPS_ARCH_ASE_M16  = 0x04000000, // MIPS-16 ISA extensions
    EF_MIPS_ARCH          = 0xF0000000, // Architecture field
    EF_MIPS_ARCH_1        = 0x00000000, // -mips1 code
    EF_MIPS_ARCH_2        = 0x10000000, // -mips2 code
    EF_MIPS_ARCH_3        = 0x20000000, // -mips3 code
    EF_MIPS_ARCH_4        = 0x30000000, // -mips4 code
    EF_MIPS_ARCH_5        = 0x40000000, // -mips5 code
    EF_MIPS_ARCH_32       = 0x50000000, // -mips32 code
    EF_MIPS_ARCH_64       = 0x60000000, // -mips64 code
    EF_MIPS_ARCH_32R2     = 0x70000000, // -mips32r2 code
    EF_MIPS_ARCH_64R2     = 0x80000000, // -mips64r2 code

    EF_PPC_EMB             = 0x80000000,
    EF_PPC_RELOCATABLE     = 0x00010000,
    EF_PPC_RELOCATABLE_LIB = 0x00008000,

    EF_PPC64_ABI_VER0 = 0x00000000, // 0 for unspecified or not using any features affected by the differences
    EF_PPC64_ABI_VER1 = 0x00000001, // 1 for original ABI using function descriptors,
    EF_PPC64_ABI_VER2 = 0x00000002, // 2 for revised ABI without function descriptors,
    EF_PPC64_ABI      = 0x00000003,

    EF_RISCV_RVC              = 0x00000001,
    EF_RISCV_FLOAT_ABI_MASK   = 0x00000006,
    EF_RISCV_FLOAT_ABI_SOFT   = 0x00000000,
    EF_RISCV_FLOAT_ABI_SINGLE = 0x00000002,
    EF_RISCV_FLOAT_ABI_DOUBLE = 0x00000004,
    EF_RISCV_FLOAT_ABI_QUAD   = 0x00000006,
    EF_RISCV_RVE              = 0x00000008,
    EF_RISCV_TSO              = 0x00000010,

    EF_SPARC_EXT_MASK = 0x00ffff00,
    EF_SPARC_32PLUS   = 0x00000100,
    EF_SPARC_SUN_US1  = 0x00000200,
    EF_SPARC_HAL_R1   = 0x00000400,
    EF_SPARC_SUN_US3  = 0x00000800,

    EF_SPARCV9_MM  = 0x00000003,
    EF_SPARCV9_TSO = 0x00000000,
    EF_SPARCV9_PSO = 0x00000001,
    EF_SPARCV9_RMO = 0x00000002,

    EF_PARISC_TRAPNIL  = 0x00010000, // trap on NULL derefs
    EF_PARISC_EXT      = 0x00020000, // program uses arch exts
    EF_PARISC_LSB      = 0x00040000, // program expects LSB mode
    EF_PARISC_WIDE     = 0x00080000, // program expects wide mode
    EF_PARISC_NO_KABP  = 0x00100000, // don't allow kernel assisted branch prediction
    EF_PARISC_LAZYSWAP = 0x00200000, // allow lazy swap allocation for dynamically allocated program segments
    EF_PARISC_ARCH     = 0x0000ffff, // architecture version
    EFA_PARISC_1_0     = 0x0000020B,
    EFA_PARISC_1_1     = 0x00000210,
    EFA_PARISC_2_0     = 0x00000214,

    EF_SH_MACH_MASK    = 0x0000001f,
    EF_SH_UNKNOWN      = 0x00000000,
    EF_SH_SH1          = 0x00000001,
    EF_SH_SH2          = 0x00000002,
    EF_SH_SH3          = 0x00000003,
    EF_SH_DSP          = 0x00000004,
    EF_SH_SH3_DSP      = 0x00000005,
    EF_SH_SH3E         = 0x00000008,
    EF_SH_SH4          = 0x00000009,
    EF_SH5             = 0x0000000A,
    EF_SH2E            = 0x0000000B,
    EF_SH4A            = 0x0000000C,
    EF_SH2A            = 0x0000000D,
    EF_SH4_NOFPU       = 0x00000010,
    EF_SH4A_NOFPU      = 0x00000011,
    EF_SH4_NOMMU_NOFPU = 0x00000012,
    EF_SH2A_NOFPU      = 0x00000013,
    EF_SH3_NOMMU       = 0x00000014,
    EF_SH2A_SH4_NOFPU  = 0x00000015,
    EF_SH2A_SH3_NOFPU  = 0x00000016,
    EF_SH2A_SH4        = 0x00000017,
    EF_SH2A_SH3E       = 0x00000018,

    EF_IA_64_MASKOS             = 0x0000000f, // OS-specific flags
    EF_IA_64_ARCH               = 0xff000000, // Arch version mask
    EF_IA_64_ARCHVER_1          = 0x01000000, // Arch version level 1 compat
    EF_IA_64_TRAPNIL            = 0x00000001, // Trap NIL pointer dereferences
    EF_IA_64_EXT                = 0x00000004, // Program uses arch extensions
    EF_IA_64_BE                 = 0x00000008, // PSR BE bit set (big-endian)
    EFA_IA_64_EAS2_3            = 0x23000000, // IA64 EAS 23
    EF_IA_64_ABI64              = 0x00000010, // 64-bit ABI
    EF_IA_64_REDUCEDFP          = 0x00000020, // Only FP6-FP11 used
    EF_IA_64_CONS_GP            = 0x00000040, // gp as program wide constant
    EF_IA_64_NOFUNCDESC_CONS_GP = 0x00000080, // And no function descriptors
    EF_IA_64_ABSOLUTE           = 0x00000100, // Load at absolute addresses

    // @formatter:on
  }
}