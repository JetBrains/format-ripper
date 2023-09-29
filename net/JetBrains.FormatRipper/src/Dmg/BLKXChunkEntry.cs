using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace JetBrains.FormatRipper.Dmg;

[SuppressMessage("ReSharper", "IdentifierTypo")]
[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct BLKXChunkEntry
{
  public UInt32 EntryType;
  public UInt32 Comment;
  public UInt64 SectorNumber;
  public UInt64 SectorCount;
  public UInt64 CompressedOffset;
  public UInt64 CompressedLength;
}