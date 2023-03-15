using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum IMAGE_SUBSYSTEM : ushort
  {
    // @formatter:off
    IMAGE_SUBSYSTEM_UNKNOWN                  =  0,  // Unknown subsystem.
    IMAGE_SUBSYSTEM_NATIVE                   =  1,  // Image doesn't require a subsystem.
    IMAGE_SUBSYSTEM_WINDOWS_GUI              =  2,  // Image runs in the Windows GUI subsystem.
    IMAGE_SUBSYSTEM_WINDOWS_CUI              =  3,  // Image runs in the Windows character subsystem.
    IMAGE_SUBSYSTEM_OS2_CUI                  =  5,  // image runs in the OS/2 character subsystem.
    IMAGE_SUBSYSTEM_POSIX_CUI                =  7,  // image runs in the Posix character subsystem.
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS           =  8,  // image is a native Win9x driver.
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           =  9,  // Image runs in the Windows CE subsystem.
    IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12,
    IMAGE_SUBSYSTEM_EFI_ROM                  = 13,
    IMAGE_SUBSYSTEM_XBOX                     = 14,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
    IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG        = 17
    // @formatter:on
  }
}