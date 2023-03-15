using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal unsafe struct CompoundFileHeader
  {
    internal fixed Byte HeaderSignature[Declarations.HeaderSignatureSize];
    internal Guid HeaderClsid;
    internal UInt16 MinorVersion;
    internal UInt16 MajorVersion;
    internal UInt16 ByteOrder;
    internal UInt16 SectorShift;
    internal UInt16 MiniSectorShift;
    internal fixed Byte Reserved[6];
    internal UInt32 NumberOfDirectorySectors;
    internal UInt32 NumberOfFatSectors;
    internal UInt32 FirstDirectorySectorLocation;
    internal UInt32 TransactionSignatureNumber;
    internal UInt32 MiniStreamCutoffSize;
    internal UInt32 FirstMiniFatSectorLocation;
    internal UInt32 NumberOfMiniFatSectors;
    internal UInt32 FirstDiFatSectorLocation;
    internal UInt32 NumberOfDiFatSectors;
  }
}