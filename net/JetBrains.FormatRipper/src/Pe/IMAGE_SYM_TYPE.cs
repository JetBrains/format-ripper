using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum IMAGE_SYM_TYPE : ushort
  {
    // @formatter:off
    IMAGE_SYM_TYPE_NULL   = 0x0000, // no type.
    IMAGE_SYM_TYPE_VOID   = 0x0001,
    IMAGE_SYM_TYPE_CHAR   = 0x0002, // type character.
    IMAGE_SYM_TYPE_SHORT  = 0x0003, // type short integer.
    IMAGE_SYM_TYPE_INT    = 0x0004,
    IMAGE_SYM_TYPE_LONG   = 0x0005,
    IMAGE_SYM_TYPE_FLOAT  = 0x0006,
    IMAGE_SYM_TYPE_DOUBLE = 0x0007,
    IMAGE_SYM_TYPE_STRUCT = 0x0008,
    IMAGE_SYM_TYPE_UNION  = 0x0009,
    IMAGE_SYM_TYPE_ENUM   = 0x000A, // enumeration.
    IMAGE_SYM_TYPE_MOE    = 0x000B, // member of enumeration.
    IMAGE_SYM_TYPE_BYTE   = 0x000C,
    IMAGE_SYM_TYPE_WORD   = 0x000D,
    IMAGE_SYM_TYPE_UINT   = 0x000E,
    IMAGE_SYM_TYPE_DWORD  = 0x000F,
    // @formatter:on
  }
}
