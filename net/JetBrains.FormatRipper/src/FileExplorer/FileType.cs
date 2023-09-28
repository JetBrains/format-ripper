using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.FileExplorer
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum FileType
  {
    Unknown = 0,
    Pe,
    Msi,
    MachO,
    Elf,
    Sh,
    Dmg
  }
}