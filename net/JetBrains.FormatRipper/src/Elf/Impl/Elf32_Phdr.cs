using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.SignatureVerifier.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct Elf32_Phdr
  {
    public UInt32 p_type; /* Segment type */
    public UInt32 p_offset; /* Segment file offset */
    public UInt32 p_vaddr; /* Segment virtual address */
    public UInt32 p_paddr; /* Segment physical address */
    public UInt32 p_filesz; /* Segment size in file */
    public UInt32 p_memsz; /* Segment size in memory */
    public UInt32 p_flags; /* Segment flags */
    public UInt32 p_align; /* Segment alignment */
  }
}