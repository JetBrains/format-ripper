using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum STT : byte
  {
    // @formatter:off
    STT_NOTYPE  =  0, // Symbol type is unspecified
    STT_OBJECT  =  1, // Symbol is a data object (variable, array, etc.)
    STT_FUNC    =  2, // Symbol is a function or other executable code
    STT_SECTION =  3, // Symbol is associated with a section
    STT_FILE    =  4, // Symbol's name is the source file associated with the object file
    STT_COMMON  =  5, // Symbol labels an uninitialized common block
    STT_TLS     =  6, // Symbol specifies a Thread-Local Storage entity
    STT_LOOS    = 10, // Start of OS-specific type
    STT_HIOS    = 12, // End of OS-specific type
    STT_LOPROC  = 13, // Start of processor-specific type
    STT_HIPROC  = 15  // End of processor-specific type
    // @formatter:on
  }
}
