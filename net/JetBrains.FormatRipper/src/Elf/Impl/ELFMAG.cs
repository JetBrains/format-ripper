using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Elf.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class ELFMAG
  {
    internal const byte ELFMAG0 = 0x7F;
    internal const byte ELFMAG1 = (byte)'E';
    internal const byte ELFMAG2 = (byte)'L';
    internal const byte ELFMAG3 = (byte)'F';
  }
}