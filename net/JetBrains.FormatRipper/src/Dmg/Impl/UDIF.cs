using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Dmg.Impl;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct UDIF
{
  internal uint Magic;                  // magic 'koly'
  internal uint Version;                // 4 (as of 2013)
  internal uint HeaderSize;             // sizeof(this) =  512 (as of 2013)
  internal uint Flags;
  internal ulong RunningDataForkOffset;
  internal ulong DataForkOffset;         // usually 0, beginning of file
  internal ulong DataForkLength;
  internal ulong RsrcForkOffset;         // resource fork offset and length
  internal ulong RsrcForkLength;
  internal uint SegmentNumber;          // Usually 1, can be 0
  internal uint SegmentCount;           // Usually 1, can be 0
  internal fixed byte SegmentID[16];
  internal uint DataChecksumType;       // Data fork checksum
  internal uint DataChecksumSize;
  internal fixed uint DataChecksum[32];
  internal ulong PlistOffset;              // Position of XML property list in file
  internal ulong PlistLength;
  internal fixed byte Reserved1[64];
  internal ulong CodeSignatureOffset;
  internal ulong CodeSignatureLength;
  internal fixed byte Reserved2[40];
  internal uint ChecksumType;           // Master checksum
  internal uint ChecksumSize;
  internal fixed uint Checksum[32];
  internal uint ImageVariant;           // Unknown, commonly 1
  internal ulong SectorCount;
  internal uint Reserved3;
  internal uint Reserved4;
  internal uint Reserved5;
}