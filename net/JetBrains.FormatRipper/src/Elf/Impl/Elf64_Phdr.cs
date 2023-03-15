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
  internal struct Elf64_Phdr
  {
    internal UInt32 p_type; /* Segment type */
    internal UInt32 p_flags; /* Segment flags */
    internal UInt64 p_offset; /* Segment file offset */
    internal UInt64 p_vaddr; /* Segment virtual address */
    internal UInt64 p_paddr; /* Segment physical address */
    internal UInt64 p_filesz; /* Segment size in file */
    internal UInt64 p_memsz; /* Segment size in memory */
    internal UInt64 p_align; /* Segment alignment */
  }
}