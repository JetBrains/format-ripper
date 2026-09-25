using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum IMAGE_SCN : uint
  {
    // @formatter:off
    IMAGE_SCN_TYPE_NO_PAD            = 0x00000008, // Reserved.
    IMAGE_SCN_CNT_CODE               = 0x00000020, // Section contains code.
    IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040, // Section contains initialized data.
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080, // Section contains uninitialized data.
    IMAGE_SCN_LNK_OTHER              = 0x00000100, // Reserved.
    IMAGE_SCN_LNK_INFO               = 0x00000200, // Section contains comments or some other type of information.
    IMAGE_SCN_LNK_REMOVE             = 0x00000800, // Section contents will not become part of image.
    IMAGE_SCN_LNK_COMDAT             = 0x00001000, // Section contents comdat.
    IMAGE_SCN_NO_DEFER_SPEC_EXC      = 0x00004000, // Reset speculative exceptions handling bits in the TLB entries for this section.
    IMAGE_SCN_GPREL                  = 0x00008000, // Section content can be accessed relative to GP
    IMAGE_SCN_MEM_FARDATA            = 0x00008000,
    IMAGE_SCN_MEM_PURGEABLE          = 0x00020000,
    IMAGE_SCN_MEM_16BIT              = 0x00020000,
    IMAGE_SCN_MEM_LOCKED             = 0x00040000,
    IMAGE_SCN_MEM_PRELOAD            = 0x00080000,
    IMAGE_SCN_ALIGN_1BYTES           = 0x00100000,
    IMAGE_SCN_ALIGN_2BYTES           = 0x00200000,
    IMAGE_SCN_ALIGN_4BYTES           = 0x00300000,
    IMAGE_SCN_ALIGN_8BYTES           = 0x00400000,
    IMAGE_SCN_ALIGN_16BYTES          = 0x00500000, // Default alignment if no others are specified.
    IMAGE_SCN_ALIGN_32BYTES          = 0x00600000,
    IMAGE_SCN_ALIGN_64BYTES          = 0x00700000,
    IMAGE_SCN_ALIGN_128BYTES         = 0x00800000,
    IMAGE_SCN_ALIGN_256BYTES         = 0x00900000,
    IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000,
    IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000,
    IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000,
    IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000,
    IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000,
    IMAGE_SCN_ALIGN_MASK             = 0x00F00000,
    IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000, // Section contains extended relocations.
    IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000, // Section can be discarded.
    IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000, // Section is not cachable.
    IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000, // Section is not pageable.
    IMAGE_SCN_MEM_SHARED             = 0x10000000, // Section is shareable.
    IMAGE_SCN_MEM_EXECUTE            = 0x20000000, // Section is executable.
    IMAGE_SCN_MEM_READ               = 0x40000000, // Section is readable.
    IMAGE_SCN_MEM_WRITE              = 0x80000000, // Section is writeable.
    // @formatter:on
  }
}
