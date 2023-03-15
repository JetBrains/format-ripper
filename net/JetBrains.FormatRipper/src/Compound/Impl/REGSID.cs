using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal enum REGSID : uint
  {
    MAXREGSID = 0xFFFFFFFA,
    NOSTREAM = 0xFFFFFFFF
  }
}