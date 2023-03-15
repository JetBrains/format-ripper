using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum IMAGE_FILE : ushort
  {
    // @formatter:off
    IMAGE_FILE_RELOCS_STRIPPED         = 0x0001, // Relocation info stripped from file.
    IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002, // File is executable  (i.e. no unresolved external references).
    IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004, // Line nunbers stripped from file.
    IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008, // Local symbols stripped from file.
    IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010, // Aggressively trim working set
    IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020, // App can handle >2gb addresses
    IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080, // Bytes of machine word are reversed.
    IMAGE_FILE_32BIT_MACHINE           = 0x0100, // 32 bit word machine.
    IMAGE_FILE_DEBUG_STRIPPED          = 0x0200, // Debugging info stripped from file in .DBG file
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400, // If Image is on removable media, copy and run from the swap file.
    IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800, // If Image is on Net, copy and run from the swap file.
    IMAGE_FILE_SYSTEM                  = 0x1000, // System File.
    IMAGE_FILE_DLL                     = 0x2000, // File is a DLL.
    IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000, // File should only be run on a UP machine
    IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000, // Bytes of machine word are reversed.
    // @formatter:on
  }
}