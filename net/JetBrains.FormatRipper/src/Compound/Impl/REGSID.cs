using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum REGSID : uint
  {
    MAXREGSID = 0xFFFFFFFA,
    NOSTREAM = 0xFFFFFFFF
  }
}