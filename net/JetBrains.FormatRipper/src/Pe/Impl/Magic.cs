using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public static class Magic
  {
    internal const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    internal const ushort IMAGE_OS2_SIGNATURE = 0x454E; // NE
    internal const ushort IMAGE_OS2_SIGNATURE_LE = 0x454C; // LE
    internal const ushort IMAGE_VXD_SIGNATURE = 0x454C; // LE

    internal const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

    internal const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
    internal const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
    internal const ushort IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107;
  }
}