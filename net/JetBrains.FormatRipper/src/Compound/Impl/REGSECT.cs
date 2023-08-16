using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum REGSECT : uint
  {
    MAXREGSECT = 0xFFFFFFFA,
    DIFSECT = 0xFFFFFFFC,
    FATSECT = 0xFFFFFFFD,
    ENDOFCHAIN = 0xFFFFFFFE,
    FREESECT = 0xFFFFFFFF
  }
}