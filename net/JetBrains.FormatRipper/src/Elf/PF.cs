using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [Flags]
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum PF : uint
  {
    // @formatter:off
    PF_X        = 0x00000001, // Segment is executable
    PF_W        = 0x00000002, // Segment is writable
    PF_R        = 0x00000004, // Segment is readable
    PF_MASKOS   = 0x0ff00000, // OS-specific
    PF_MASKPROC = 0xf0000000  // Processor-specific
    // @formatter:on
  }
}
