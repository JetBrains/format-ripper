using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.MachO.Impl
{
  // Note(ww898): See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

  /* LC_DYSYMTAB */
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct dysymtab_command
  {
    internal UInt32 cmd; /* LC_DYSYMTAB */
    internal UInt32 cmdsize; /* sizeof(struct dysymtab_command) */
    internal UInt32 ilocalsym; /* index to local symbols */
    internal UInt32 nlocalsym; /* number of local symbols */
    internal UInt32 iextdefsym; /* index to externally defined symbols */
    internal UInt32 nextdefsym; /* number of externally defined symbols */
    internal UInt32 iundefsym; /* index to undefined symbols */
    internal UInt32 nundefsym; /* number of undefined symbols */
    internal UInt32 tocoff; /* file offset to table of contents */
    internal UInt32 ntoc; /* number of entries in table of contents */
    internal UInt32 modtaboff; /* file offset to module table */
    internal UInt32 nmodtab; /* number of module table entries */
    internal UInt32 extrefsymoff; /* offset to referenced symbol table */
    internal UInt32 nextrefsyms; /* number of referenced symbol table entries */
    internal UInt32 indirectsymoff; /* file offset to the indirect symbol table */
    internal UInt32 nindirectsyms; /* number of indirect symbol table entries */
    internal UInt32 extreloff; /* offset to external relocation entries */
    internal UInt32 nextrel; /* number of external relocation entries */
    internal UInt32 locreloff; /* offset to local relocation entries */
    internal UInt32 nlocrel; /* number of local relocation entries */
  }
}
