using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Compound.Impl
{
  [SuppressMessage("ReSharper", "IdentifierTypo")]
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
  [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  public unsafe struct CompoundFileDirectoryEntry
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

  // Used to store as json
  public class CompoundFileDirectoryEntryDataHolder
  {
    public byte[] DirectoryEntryName { get; }
    public ushort DirectoryEntryNameLength { get; }
    public byte ObjectType { get; }
    public byte ColorFlag { get; }
    public uint LeftSiblingId { get; }
    public uint RightSiblingId { get; }
    public uint ChildId { get; }
    public Guid Clsid { get; }
    public uint StateBits { get; }
    public ulong CreationTime { get; }
    public ulong ModifiedTime { get; }
    public uint StartingSectorLocation { get; }
    public ulong StreamSize { get; }

    public CompoundFileDirectoryEntryDataHolder(
      byte[] directoryEntryName,
      ushort directoryEntryNameLength,
      byte objectType,
      byte colorFlag,
      uint leftSiblingId,
      uint rightSiblingId,
      uint childId,
      Guid clsid,
      uint stateBits,
      ulong creationTime,
      ulong modifiedTime,
      uint startingSectorLocation,
      ulong streamSize
    )
    {
      DirectoryEntryName = directoryEntryName;
      DirectoryEntryNameLength = directoryEntryNameLength;
      ObjectType = objectType;
      ColorFlag = colorFlag;
      LeftSiblingId = leftSiblingId;
      RightSiblingId = rightSiblingId;
      ChildId = childId;
      Clsid = clsid;
      StateBits = stateBits;
      CreationTime = creationTime;
      ModifiedTime = modifiedTime;
      StartingSectorLocation = startingSectorLocation;
      StreamSize = streamSize;
    }

    public static CompoundFileDirectoryEntryDataHolder GetInstance(CompoundFileDirectoryEntry cfde)
    {
      byte[] directoryEntryName = new byte[Declarations.DirectoryEntryNameSize];

      unsafe
      {
        for (var i = 0; i < MemoryUtil.GetLeU2(cfde.DirectoryEntryNameLength); i++)
        {
          directoryEntryName[i] = cfde.DirectoryEntryName[i];
        }
      }

      return new CompoundFileDirectoryEntryDataHolder(
        directoryEntryName,
        cfde.DirectoryEntryNameLength,
        cfde.ObjectType,
        cfde.ColorFlag,
        cfde.LeftSiblingId,
        cfde.RightSiblingId,
        cfde.ChildId,
        cfde.Clsid,
        cfde.StateBits,
        cfde.CreationTime,
        cfde.ModifiedTime,
        cfde.StartingSectorLocation,
        cfde.StreamSize
      );
    }
  }
}