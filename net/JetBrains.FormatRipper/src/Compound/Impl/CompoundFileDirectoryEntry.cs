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
  internal unsafe struct CompoundFileDirectoryEntry
  {
    internal fixed Byte DirectoryEntryName[Declarations.DirectoryEntryNameSize];
    internal UInt16 DirectoryEntryNameLength;
    internal Byte ObjectType;
    internal Byte ColorFlag;
    internal UInt32 LeftSiblingId;
    internal UInt32 RightSiblingId;
    internal UInt32 ChildId;
    internal Guid Clsid;
    internal UInt32 StateBits;
    internal UInt64 CreationTime;
    internal UInt64 ModifiedTime;
    internal UInt32 StartingSectorLocation;
    internal UInt64 StreamSize;
  }
}