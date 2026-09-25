using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  internal static class ImageSymbol
  {
    internal const ushort N_BTMASK = 0x000F;
    internal const int N_BTSHFT = 4;
  }
}
