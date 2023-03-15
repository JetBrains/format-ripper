using System;
using System.Diagnostics.CodeAnalysis;

namespace JetBrains.FormatRipper.FileExplorer
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [Flags]
  public enum FileProperties : uint
  {
    UnknownType = 0x0,
    ExecutableType = 0x1,
    SharedLibraryType = 0x2,
    BundleType = 0x3,

    TypeMask = 0xFF,

    MultiArch = 0x20000000,
    Managed = 0x40000000,
    Signed = 0x80000000
  }
}