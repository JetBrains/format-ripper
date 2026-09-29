using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class PN
  {
    internal const ushort PN_XNUM = 0xffff; /* Extended numbering, the actual number of program headers is in sh_info of the section header 0 */
  }
}