using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-201/osfmk/mach/vm_prot.h.auto.html

  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal unsafe struct segment_command_64
  {
    internal fixed byte segname[16]; /* segment name */
    internal UInt64 vmaddr; /* memory address of this segment */
    internal UInt64 vmsize; /* memory size of this segment */
    internal UInt64 fileoff; /* file offset of this segment */
    internal UInt64 filesize; /* amount to map from the file */
    internal UInt32 maxprot; /* maximum VM protection */
    internal UInt32 initprot; /* initial VM protection */
    internal UInt32 nsects; /* number of sections in segment */
    internal UInt32 flags; /* flags */
  }
}