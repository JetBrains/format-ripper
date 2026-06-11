using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct Elf64_Sym
  {
    internal UInt32 st_name;  /* Symbol name (string tbl index) */
    internal Byte   st_info;  /* Symbol type and binding: high nibble = STB_* binding (>> 4), low nibble = STT_* type (& 0xf) */
    internal Byte   st_other; /* Symbol visibility */
    internal UInt16 st_shndx; /* Section index */
    internal UInt64 st_value; /* Symbol value */
    internal UInt64 st_size;  /* Symbol size */
  }
}
