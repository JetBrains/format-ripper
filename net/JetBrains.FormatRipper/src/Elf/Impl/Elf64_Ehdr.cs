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
  internal struct Elf64_Ehdr
  {
    internal UInt16 e_type; /* Object file type */
    internal UInt16 e_machine; /* Architecture */
    internal UInt32 e_version; /* Object file version */
    internal UInt64 e_entry; /* Entry point virtual address */
    internal UInt64 e_phoff; /* Program header table file offset */
    internal UInt64 e_shoff; /* Section header table file offset */
    internal UInt32 e_flags; /* Processor-specific flags */
    internal UInt16 e_ehsize; /* ELF header size in bytes */
    internal UInt16 e_phentsize; /* Program header table entry size */
    internal UInt16 e_phnum; /* Program header table entry count */
    internal UInt16 e_shentsize; /* Section header table entry size */
    internal UInt16 e_shnum; /* Section header table entry count */
    internal UInt16 e_shstrndx; /* Section header string table index */
  }
}