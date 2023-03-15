using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum ELFDATA : byte
  {
    ELFDATANONE = 0, // Invalid data encoding.
    ELFDATA2LSB = 1, // Little-endian object file
    ELFDATA2MSB = 2  // Big-endian object file
  }
}