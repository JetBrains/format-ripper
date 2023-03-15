using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal unsafe struct IMAGE_SECTION_HEADER
  {
    internal fixed Byte Name[ImageSection.IMAGE_SIZEOF_SHORT_NAME];
    internal UInt32 VirtualSize; // UInt32 PhysicalAddress;
    internal UInt32 VirtualAddress;
    internal UInt32 SizeOfRawData;
    internal UInt32 PointerToRawData;
    internal UInt32 PointerToRelocations;
    internal UInt32 PointerToLinenumbers;
    internal UInt16 NumberOfRelocations;
    internal UInt16 NumberOfLinenumbers;
    internal UInt32 Characteristics;
  }
}