using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Pe.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 2)]
  internal struct IMAGE_SYMBOL
  {
    internal UInt32 Short; // if 0, use Long, otherwise Short and Long are the ShortName[8]
    internal UInt32 Long; // offset into string table
    internal UInt32 Value;
    internal UInt16 SectionNumber; // declared as SHORT in the original header
    internal UInt16 Type;
    internal Byte StorageClass;
    internal Byte NumberOfAuxSymbols;
  }
}
