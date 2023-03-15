using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.SignatureVerifier.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct Elf64_Ehdr
  {
    public UInt16 e_type; /* Object file type */
    public UInt16 e_machine; /* Architecture */
    public UInt32 e_version; /* Object file version */
    public UInt64 e_entry; /* Entry point virtual address */
    public UInt64 e_phoff; /* Program header table file offset */
    public UInt64 e_shoff; /* Section header table file offset */
    public UInt32 e_flags; /* Processor-specific flags */
    public UInt16 e_ehsize; /* ELF header size in bytes */
    public UInt16 e_phentsize; /* Program header table entry size */
    public UInt16 e_phnum; /* Program header table entry count */
    public UInt16 e_shentsize; /* Section header table entry size */
    public UInt16 e_shnum; /* Section header table entry count */
    public UInt16 e_shstrndx; /* Section header string table index */
  }
}