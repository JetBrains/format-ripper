using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum SEC : uint
  {
    // @formatter:off
    SECTION_ATTRIBUTES     = 0xffffff00, /* 24 section attributes */
    SECTION_ATTRIBUTES_USR = 0xff000000, /* User setable attributes */
    SECTION_ATTRIBUTES_SYS = 0x00ffff00, /* system setable attributes */
    SECTION_TYPE           = 0x000000ff, /* 256 section types */
    // @formatter:on

    /* Values for the SECTION_TYPE(0x000000ff) bits */
    // @formatter:off
    S_REGULAR                             = 0x00, /* regular section */
    S_ZEROFILL                            = 0x01, /* zero fill on demand section */
    S_CSTRING_LITERALS                    = 0x02, /* section with only literal C strings */
    S_4BYTE_LITERALS                      = 0x03, /* section with only 4 byte literals */
    S_8BYTE_LITERALS                      = 0x04, /* section with only 8 byte literals */
    S_LITERAL_POINTERS                    = 0x05, /* section with only pointers to literals */
    S_NON_LAZY_SYMBOL_POINTERS            = 0x06, /* section with only non-lazy symbol pointers */
    S_LAZY_SYMBOL_POINTERS                = 0x07, /* section with only lazy symbol pointers */
    S_SYMBOL_STUBS                        = 0x08, /* section with only symbol stubs, byte size of stub in the reserved2 field */
    S_MOD_INIT_FUNC_POINTERS              = 0x09, /* section with only function pointers for initialization */
    S_MOD_TERM_FUNC_POINTERS              = 0x0a, /* section with only function pointers for termination */
    S_COALESCED                           = 0x0b, /* section contains symbols that are to be coalesced */
    S_GB_ZEROFILL                         = 0x0c, /* zero fill on demand section (that can be larger than 4 gigabytes) */
    S_INTERPOSING                         = 0x0d, /* section with only pairs of function pointers for interposing */
    S_16BYTE_LITERALS                     = 0x0e, /* section with only 16 byte literals */
    S_DTRACE_DOF                          = 0x0f, /* section contains DTrace Object Format */
    S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10, /* section with only lazy symbol pointers to lazy loaded dylibs */
    S_THREAD_LOCAL_REGULAR                = 0x11, /* template of initial values for TLVs */
    S_THREAD_LOCAL_ZEROFILL               = 0x12, /* template of initial values for TLVs */
    S_THREAD_LOCAL_VARIABLES              = 0x13, /* TLV descriptors */
    S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14, /* pointers to TLV descriptors */
    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15, /* functions to call to initialize TLV values */
    S_INIT_FUNC_OFFSETS                   = 0x16, /* 32-bit offsets to initializers */
    // @formatter:on

    /* Values for the SECTION_ATTRIBUTES_USR(0xff000000) bits */
    // @formatter:off
    S_ATTR_PURE_INSTRUCTIONS   = 0x80000000, /* section contains only true machine instructions */
    S_ATTR_NO_TOC              = 0x40000000, /* section contains coalesced symbols that are not to be in a ranlib table of contents */
    S_ATTR_STRIP_STATIC_SYMS   = 0x20000000, /* ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
    S_ATTR_NO_DEAD_STRIP       = 0x10000000, /* no dead stripping */
    S_ATTR_LIVE_SUPPORT        = 0x08000000, /* blocks are live if they reference live blocks */
    S_ATTR_SELF_MODIFYING_CODE = 0x04000000, /* Used with i386 code stubs written on by dyld */
    S_ATTR_DEBUG               = 0x02000000, /* a debug section */
    // @formatter:on

    /* Values for the SECTION_ATTRIBUTES_SYS(0x00ffff00) bits */
    // @formatter:off
    S_ATTR_SOME_INSTRUCTIONS   = 0x00000400, /* section contains some machine instructions */
    S_ATTR_EXT_RELOC           = 0x00000200, /* section has external relocation entries */
    S_ATTR_LOC_RELOC           = 0x00000100  /* section has local relocation entries */
    // @formatter:on
  }
}
