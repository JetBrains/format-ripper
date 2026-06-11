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
  internal struct Elf64_Shdr
  {
    internal UInt32 sh_name; /* Section name (string tbl index) */
    internal UInt32 sh_type; /* Section type */
    internal UInt64 sh_flags; /* Section flags */
    internal UInt64 sh_addr; /* Section virtual addr at execution */
    internal UInt64 sh_offset; /* Section file offset */
    internal UInt64 sh_size; /* Section size in bytes */
    internal UInt32 sh_link; /* Link to another section */
    internal UInt32 sh_info; /* Additional section information */
    internal UInt64 sh_addralign; /* Section alignment */
    internal UInt64 sh_entsize; /* Entry size if section holds table */
  }
}
