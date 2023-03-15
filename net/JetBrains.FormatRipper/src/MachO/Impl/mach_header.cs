using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct mach_header
  {
    internal UInt32 cputype; /* cpu specifier */
    internal UInt32 cpusubtype; /* machine specifier */
    internal UInt32 filetype; /* type of file */
    internal UInt32 ncmds; /* number of load commands */
    internal UInt32 sizeofcmds; /* the size of all the load commands */
    internal UInt32 flags; /* flags */
  }
}