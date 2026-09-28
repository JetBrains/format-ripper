using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.MachO.Impl
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  internal enum TOOL : uint
  {
    // @formatter:off
    TOOL_CLANG = 1,
    TOOL_SWIFT = 2,
    TOOL_LD    = 3,
    TOOL_LLD   = 4,
    // @formatter:on
  }
}
