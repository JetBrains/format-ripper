using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum IMAGE_SYM : ushort
  {
    // @formatter:off
    IMAGE_SYM_UNDEFINED   = 0x0000, // Symbol is undefined or is common.
    IMAGE_SYM_SECTION_MAX = 0xFEFF, // Values 0xFF00-0xFFFF are special
    IMAGE_SYM_DEBUG       = 0xFFFE, // Symbol is a special debug item.
    IMAGE_SYM_ABSOLUTE    = 0xFFFF, // Symbol is an absolute value.
    // @formatter:on
  }
}
