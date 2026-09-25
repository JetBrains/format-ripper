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
  internal struct IMAGE_EXPORT_DIRECTORY
  {
    internal UInt32 Characteristics;
    internal UInt32 TimeDateStamp;
    internal UInt16 MajorVersion;
    internal UInt16 MinorVersion;
    internal UInt32 Name;
    internal UInt32 Base;
    internal UInt32 NumberOfFunctions;
    internal UInt32 NumberOfNames;
    internal UInt32 AddressOfFunctions; // RVA from base of image
    internal UInt32 AddressOfNames; // RVA from base of image
    internal UInt32 AddressOfNameOrdinals; // RVA from base of image
  }
}
