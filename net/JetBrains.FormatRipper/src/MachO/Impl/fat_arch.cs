using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct fat_arch
  {
    internal UInt32 cputype; /* cpu specifier (int) */
    internal UInt32 cpusubtype; /* machine specifier (int) */
    internal UInt32 offset; /* file offset to this object file */
    internal UInt32 size; /* size of this object file */
    internal UInt32 align; /* alignment as a power of 2 */
  }
}