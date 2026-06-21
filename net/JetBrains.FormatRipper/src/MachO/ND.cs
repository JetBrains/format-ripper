using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/nlist.h
  // Note(ww898): See https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h

  // The n_desc field contains several overlapping fields: the reference type and the flag bits, the library ordinal
  // for the undefined symbols in the MH_TWOLEVEL images, the alignment for the common symbols and the .stabs desc
  // value for the entries with any of the N_STAB(0xe0) bits set.
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "ShiftExpressionZeroLeftOperand")]
  [Flags]
  public enum ND : ushort
  {
    // @formatter:off
    LIBRARY_ORDINAL = 0xff00, /* mask for the library ordinal bits of the undefined symbols */
    COMM_ALIGN      = 0x0f00, /* mask for the alignment power of two bits of the common symbols */
    REFERENCE_TYPE  = 0x0007, /* mask for the reference type bits of the undefined symbols */
    // @formatter:on

    /* Values for the REFERENCE_TYPE(0x0007) bits */
    // @formatter:off
    REFERENCE_FLAG_UNDEFINED_NON_LAZY         = 0,
    REFERENCE_FLAG_UNDEFINED_LAZY             = 1,
    REFERENCE_FLAG_DEFINED                    = 2,
    REFERENCE_FLAG_PRIVATE_DEFINED            = 3,
    REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 4,
    REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     = 5,
    // @formatter:on

    /* Values for the LIBRARY_ORDINAL(0xff00) bits, the ordinals start from 1 and reference the LC_LOAD_DYLIB,
       LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB and LC_LAZY_LOAD_DYLIB load commands in the order
       they appear in the headers */
    // @formatter:off
    SELF_LIBRARY_ORDINAL   = 0x00 << 8, /* the undefined symbol is defined in the same image */
    MAX_LIBRARY_ORDINAL    = 0xfd << 8, /* the maximum library ordinal */
    DYNAMIC_LOOKUP_ORDINAL = 0xfe << 8, /* the symbol is looked up with the flat namespace semantics, it is still a valid library ordinal in the images built before Mac OS X 10.3 */
    EXECUTABLE_ORDINAL     = 0xff << 8, /* the symbol refers to the executable which loads the image */
    // @formatter:on

    /* Flag bits, the upper ones overlap the LIBRARY_ORDINAL(0xff00) and COMM_ALIGN(0x0f00) bits */
    // @formatter:off
    N_ARM_THUMB_DEF        = 0x0008, /* symbol is a Thumb function (ARM) */
    REFERENCED_DYNAMICALLY = 0x0010, /* symbol is referenced by a dynamically bound object and must not be stripped */
    N_NO_DEAD_STRIP        = 0x0020, /* symbol is not to be dead stripped, MH_OBJECT only */
    N_DESC_DISCARDED       = 0x0020, /* symbol is discarded, used by the dynamic link editor in memory only */
    N_WEAK_REF             = 0x0040, /* symbol is weak referenced */
    N_WEAK_DEF             = 0x0080, /* coalesed symbol is a weak definition */
    N_REF_TO_WEAK          = 0x0080, /* reference to a weak symbol */
    N_SYMBOL_RESOLVER      = 0x0100, /* symbol is a resolver function which must be called to get the real address, MH_OBJECT only */
    N_ALT_ENTRY            = 0x0200, /* symbol is pinned to the previous content */
    N_COLD_FUNC            = 0x0400  /* symbol is used infrequently and should be ordered towards the end of the section */
    // @formatter:on
  }
}