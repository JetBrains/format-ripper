using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/machine.h.auto.html

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum CPU_TYPE : uint
  {
    // @formatter:off
    CPU_ARCH_MASK  = 0xff000000, /* mask for architecture bits */
    CPU_ARCH_ABI64 = 0x01000000, /* 64 bit ABI */
    // @formatter:on

    // @formatter:off
    CPU_TYPE_VAX       = 1,
    CPU_TYPE_ROMP      = 2,
    CPU_TYPE_MC680x0   = 6,
    CPU_TYPE_X86       = 7,
    CPU_TYPE_I386      = CPU_TYPE_X86, /* compatibility */
    CPU_TYPE_X86_64    = CPU_TYPE_X86 | CPU_ARCH_ABI64,
    CPU_TYPE_MIPS      = 8,
    CPU_TYPE_MC98000   = 10,
    CPU_TYPE_HPPA      = 11,
    CPU_TYPE_ARM       = 12,
    CPU_TYPE_ARM64     = CPU_TYPE_ARM | CPU_ARCH_ABI64,
    CPU_TYPE_MC88000   = 13,
    CPU_TYPE_SPARC     = 14,
    CPU_TYPE_I860      = 15,
    CPU_TYPE_ALPHA     = 16,
    CPU_TYPE_POWERPC   = 18,
    CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
    // @formatter:off
  }
}