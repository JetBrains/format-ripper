using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Dmg
{
  // https://pkg.go.dev/github.com/blacktop/go-apfs/pkg/disk/dmg
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public unsafe struct UDIFResourceFile
  {
    internal fixed byte udifSignature[4];
    internal UInt32 Version;
    internal UInt32 HeaderSize;
    internal UInt32 Flags;
    internal UInt64 RunningDataForkOffset;
    internal UInt64 DataForkOffset;
    internal UInt64 DataForkLength;
    internal UInt64 RsrcForkOffset;
    internal UInt64 RsrcForkLength;
    internal UInt32 SegmentNumber;
    internal UInt32 SegmentCount;
    internal Guid SegmentID;

    internal UInt32 DataChecksumType;
    internal UInt32 DataChecksumSize;
    internal fixed UInt32 DataChecksum[32];

    internal UInt64 PlistOffset;
    internal UInt64 PlistLength;

    internal fixed byte Reserved1[64];

    internal UInt64 CodeSignatureOffset;
    internal UInt64 CodeSignatureLength;

    internal fixed byte Reserved2[40];

    internal UDIFChecksum MasterChecksum;

    internal UInt32 ImageVariant;
    internal UInt64 SectorCount;

    internal UInt32 Reserved3;
    internal UInt32 Reserved4;
    internal UInt32 Reserved5;
  }
}