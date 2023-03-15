using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/machine.h.auto.html

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "ShiftExpressionZeroLeftOperand")]
  [Flags]
  public enum CPU_SUBTYPE : uint
  {
    CPU_SUBTYPE_MASK = 0xff000000, /* mask for feature flags */
    CPU_SUBTYPE_LIB64 = 0x80000000, /* 64 bit libraries */

    // @formatter:off
    CPU_SUBTYPE_VAX_ALL =  0,
    CPU_SUBTYPE_VAX780  =  1,
    CPU_SUBTYPE_VAX785  =  2,
    CPU_SUBTYPE_VAX750  =  3,
    CPU_SUBTYPE_VAX730  =  4,
    CPU_SUBTYPE_UVAXI   =  5,
    CPU_SUBTYPE_UVAXII  =  6,
    CPU_SUBTYPE_VAX8200 =  7,
    CPU_SUBTYPE_VAX8500 =  8,
    CPU_SUBTYPE_VAX8600 =  9,
    CPU_SUBTYPE_VAX8650 = 10,
    CPU_SUBTYPE_VAX8800 = 11,
    CPU_SUBTYPE_UVAXIII = 12,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_MC680x0_ALL  = 1,
    CPU_SUBTYPE_MC68030      = 1, /* compat */
    CPU_SUBTYPE_MC68040      = 2,
    CPU_SUBTYPE_MC68030_ONLY = 3,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_I386_ALL       =  3 + (0 << 4),
    CPU_SUBTYPE_386            =  3 + (0 << 4),
    CPU_SUBTYPE_486            =  4 + (0 << 4),
    CPU_SUBTYPE_486SX          =  4 + (8 << 4),
    CPU_SUBTYPE_586            =  5 + (0 << 4),
    CPU_SUBTYPE_PENT           =  5 + (0 << 4),
    CPU_SUBTYPE_PENTPRO        =  6 + (1 << 4),
    CPU_SUBTYPE_PENTII_M3      =  6 + (3 << 4),
    CPU_SUBTYPE_PENTII_M5      =  6 + (5 << 4),
    CPU_SUBTYPE_CELERON        =  7 + (6 << 4),
    CPU_SUBTYPE_CELERON_MOBILE =  7 + (7 << 4),
    CPU_SUBTYPE_PENTIUM_3      =  8 + (0 << 4),
    CPU_SUBTYPE_PENTIUM_3_M    =  8 + (1 << 4),
    CPU_SUBTYPE_PENTIUM_3_XEON =  8 + (2 << 4),
    CPU_SUBTYPE_PENTIUM_M      =  9 + (0 << 4),
    CPU_SUBTYPE_PENTIUM_4      = 10 + (0 << 4),
    CPU_SUBTYPE_PENTIUM_4_M    = 10 + (1 << 4),
    CPU_SUBTYPE_ITANIUM        = 11 + (0 << 4),
    CPU_SUBTYPE_ITANIUM_2      = 11 + (1 << 4),
    CPU_SUBTYPE_XEON           = 12 + (0 << 4),
    CPU_SUBTYPE_XEON_MP        = 12 + (1 << 4),
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_X86_ALL    = 3,
    CPU_SUBTYPE_X86_64_ALL = 3,
    CPU_SUBTYPE_X86_ARCH1  = 4,
    CPU_SUBTYPE_X86_64_H   = 8, /* Haswell feature subset */
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_MIPS_ALL    = 0,
    CPU_SUBTYPE_MIPS_R2300  = 1,
    CPU_SUBTYPE_MIPS_R2600  = 2,
    CPU_SUBTYPE_MIPS_R2800  = 3,
    CPU_SUBTYPE_MIPS_R2000a = 4, /* pmax */
    CPU_SUBTYPE_MIPS_R2000  = 5,
    CPU_SUBTYPE_MIPS_R3000a = 6, /* 3max */
    CPU_SUBTYPE_MIPS_R3000  = 7,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_MC98000_ALL = 0,
    CPU_SUBTYPE_MC98601     = 1,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_HPPA_ALL    = 0,
    CPU_SUBTYPE_HPPA_7100   = 0, /* compat */
    CPU_SUBTYPE_HPPA_7100LC = 1,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_MC88000_ALL = 0,
    CPU_SUBTYPE_MC88100     = 1,
    CPU_SUBTYPE_MC88110     = 2,
    // @formatter:on

    CPU_SUBTYPE_SPARC_ALL = 0,

    CPU_SUBTYPE_I860_ALL = 0,
    CPU_SUBTYPE_I860_860 = 1,

    // @formatter:off
    CPU_SUBTYPE_POWERPC_ALL   =   0,
    CPU_SUBTYPE_POWERPC_601   =   1,
    CPU_SUBTYPE_POWERPC_602   =   2,
    CPU_SUBTYPE_POWERPC_603   =   3,
    CPU_SUBTYPE_POWERPC_603e  =   4,
    CPU_SUBTYPE_POWERPC_603ev =   5,
    CPU_SUBTYPE_POWERPC_604   =   6,
    CPU_SUBTYPE_POWERPC_604e  =   7,
    CPU_SUBTYPE_POWERPC_620   =   8,
    CPU_SUBTYPE_POWERPC_750   =   9,
    CPU_SUBTYPE_POWERPC_7400  =  10,
    CPU_SUBTYPE_POWERPC_7450  =  11,
    CPU_SUBTYPE_POWERPC_970   = 100,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_ARM_ALL    =  0,
    CPU_SUBTYPE_ARM_V4T    =  5,
    CPU_SUBTYPE_ARM_V6     =  6,
    CPU_SUBTYPE_ARM_V5TEJ  =  7,
    CPU_SUBTYPE_ARM_XSCALE =  8,
    CPU_SUBTYPE_ARM_V7     =  9,
    CPU_SUBTYPE_ARM_V7F    = 10, /* Cortex A9 */
    CPU_SUBTYPE_ARM_V7S    = 11, /* Swift */
    CPU_SUBTYPE_ARM_V7K    = 12,
    CPU_SUBTYPE_ARM_V6M    = 14, /* Not meant to be run under xnu */
    CPU_SUBTYPE_ARM_V7M    = 15, /* Not meant to be run under xnu */
    CPU_SUBTYPE_ARM_V7EM   = 16, /* Not meant to be run under xnu */
    CPU_SUBTYPE_ARM_V8     = 13,
    // @formatter:on

    // @formatter:off
    CPU_SUBTYPE_ARM64_ALL = 0,
    CPU_SUBTYPE_ARM64_V8  = 1,
    CPU_SUBTYPE_ARM64_E   = 2,
    // @formatter:on
  }
}