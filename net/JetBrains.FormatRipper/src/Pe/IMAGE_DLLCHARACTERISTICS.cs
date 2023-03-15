using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum IMAGE_DLLCHARACTERISTICS : ushort
  {
    // @formatter:off
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020, // Image can handle a high entropy 64-bit virtual address space.
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040, // DLL can move.
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080, // Code Integrity Image
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100, // Image is NX compatible
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200, // Image understands isolation and doesn't want it
    IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400, // Image does not use SEH.  No SE handler may reside in this image
    IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800, // Do not bind this image.
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER          = 0x1000, // Image should execute in an AppContainer
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000, // Driver uses WDM model
    IMAGE_DLLCHARACTERISTICS_GUARD_CF              = 0x4000, // Image supports Control Flow Guard.
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
    // @formatter:on
  }
}