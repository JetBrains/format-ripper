using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.SignatureVerifier.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct Elf64_Phdr
  {
    public UInt32 p_type; /* Segment type */
    public UInt32 p_flags; /* Segment flags */
    public UInt64 p_offset; /* Segment file offset */
    public UInt64 p_vaddr; /* Segment virtual address */
    public UInt64 p_paddr; /* Segment physical address */
    public UInt64 p_filesz; /* Segment size in file */
    public UInt64 p_memsz; /* Segment size in memory */
    public UInt64 p_align; /* Segment alignment */
  }
}