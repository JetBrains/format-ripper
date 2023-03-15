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
  internal struct IMAGE_OPTIONAL_HEADER32
  {
    internal Byte MajorLinkerVersion;
    internal Byte MinorLinkerVersion;
    internal UInt32 SizeOfCode;
    internal UInt32 SizeOfInitializedData;
    internal UInt32 SizeOfUninitializedData;
    internal UInt32 AddressOfEntryPoint;
    internal UInt32 BaseOfCode;
    internal UInt32 BaseOfData;
    internal UInt32 ImageBase;
    internal UInt32 SectionAlignment;
    internal UInt32 FileAlignment;
    internal UInt16 MajorOperatingSystemVersion;
    internal UInt16 MinorOperatingSystemVersion;
    internal UInt16 MajorImageVersion;
    internal UInt16 MinorImageVersion;
    internal UInt16 MajorSubsystemVersion;
    internal UInt16 MinorSubsystemVersion;
    internal UInt32 Win32VersionValue;
    internal UInt32 SizeOfImage;
    internal UInt32 SizeOfHeaders;
    internal UInt32 CheckSum;
    internal UInt16 Subsystem;
    internal UInt16 DllCharacteristics;
    internal UInt32 SizeOfStackReserve;
    internal UInt32 SizeOfStackCommit;
    internal UInt32 SizeOfHeapReserve;
    internal UInt32 SizeOfHeapCommit;
    internal UInt32 LoaderFlags;
    internal UInt32 NumberOfRvaAndSizes;
  }
}