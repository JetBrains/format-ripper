using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/nlist.h

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct nlist_64
  {
    internal UInt32 n_strx;  /* index into the string table */
    internal Byte n_type;  /* type flag: N_STAB(0xe0) | N_PEXT(0x10) | N_TYPE(0x0e) | N_EXT(0x01) */
    internal Byte   n_sect;  /* section number or NO_SECT */
    internal UInt16 n_desc;  /* see <mach-o/stab.h> */
    internal UInt64 n_value; /* value of this symbol (or stab offset) */
  }
}
