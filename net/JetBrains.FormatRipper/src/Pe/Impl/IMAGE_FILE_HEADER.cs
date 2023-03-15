using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential)]
  internal struct IMAGE_FILE_HEADER
  {
    internal UInt16 Machine;
    internal UInt16 NumberOfSections;
    internal UInt32 TimeDateStamp;
    internal UInt32 PointerToSymbolTable;
    internal UInt32 NumberOfSymbols;
    internal UInt16 SizeOfOptionalHeader;
    internal UInt16 Characteristics;
  }
}