using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): https://stackoverflow.com/questions/65731126/how-to-understand-the-comments-about-fat-arch-64-in-mach-o-fat-h

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct fat_arch_64
  {
    internal UInt32 cputype; /* cpu specifier (int) */
    internal UInt32 cpusubtype; /* machine specifier (int) */
    internal UInt64 offset; /* file offset to this object file */
    internal UInt64 size; /* size of this object file */
    internal UInt32 align; /* alignment as a power of 2 */
    internal UInt32 reserved; /* reserved */
  }
}