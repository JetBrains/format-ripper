using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal enum EV : byte
  {
    // @formatter:off
    EV_NONE    = 0,
    EV_CURRENT = 1
    // @formatter:on
  }
}