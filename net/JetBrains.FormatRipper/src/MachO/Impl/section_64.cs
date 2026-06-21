using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  /* for 64-bit architectures */
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal unsafe struct section_64
  {
    internal fixed byte sectname[16]; /* name of this section */
    internal fixed byte segname[16]; /* segment this section goes in */
    internal UInt64 addr; /* memory address of this section */
    internal UInt64 size; /* size in bytes of this section */
    internal UInt32 offset; /* file offset of this section */
    internal UInt32 align; /* section alignment (power of 2) */
    internal UInt32 reloff; /* file offset of relocation entries */
    internal UInt32 nreloc; /* number of relocation entries */
    internal UInt32 flags; /* flags (section type and attributes) */
    internal UInt32 reserved1; /* reserved (for offset or index) */
    internal UInt32 reserved2; /* reserved (for count or sizeof) */
    internal UInt32 reserved3; /* reserved */
  }
}
