using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum IMAGE_SYM_DTYPE : ushort
  {
    // @formatter:off
    IMAGE_SYM_DTYPE_NULL     = 0, // no derived type.
    IMAGE_SYM_DTYPE_POINTER  = 1, // pointer.
    IMAGE_SYM_DTYPE_FUNCTION = 2, // function.
    IMAGE_SYM_DTYPE_ARRAY    = 3, // array.
    // @formatter:on
  }
}
