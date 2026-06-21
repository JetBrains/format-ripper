using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  /* LC_SYMTAB */
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct symtab_command
  {
    internal UInt32 cmd; /* type of load command */
    internal UInt32 cmdsize; /* total size of command in bytes */
    internal UInt32 symoff; /* symbol table offset */
    internal UInt32 nsyms; /* number of symbol table entries */
    internal UInt32 stroff; /* string table offset */
    internal UInt32 strsize; /* string table size in bytes */
  }
}
