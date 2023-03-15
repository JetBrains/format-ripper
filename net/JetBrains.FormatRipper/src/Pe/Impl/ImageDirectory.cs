using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class ImageDirectory
  {
    internal const uint IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

    // @formatter:off
    internal const uint IMAGE_DIRECTORY_ENTRY_EXPORT         =  0; // Export Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_IMPORT         =  1; // Import Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_RESOURCE       =  2; // Resource Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_EXCEPTION      =  3; // Exception Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_SECURITY       =  4; // Security Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_BASERELOC      =  5; // Base Relocation Table
    internal const uint IMAGE_DIRECTORY_ENTRY_DEBUG          =  6; // Debug Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_COPYRIGHT      =  7; // (X86 usage)
    internal const uint IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   =  7; // Architecture Specific Data
    internal const uint IMAGE_DIRECTORY_ENTRY_GLOBALPTR      =  8; // RVA of GP
    internal const uint IMAGE_DIRECTORY_ENTRY_TLS            =  9; // TLS Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10; // Load Configuration Directory
    internal const uint IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11; // Bound Import Directory in headers
    internal const uint IMAGE_DIRECTORY_ENTRY_IAT            = 12; // Import Address Table
    internal const uint IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13; // Delay Load Import Descriptors
    internal const uint IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14; // COM Runtime descriptor
    // @formatter:on
  }
}