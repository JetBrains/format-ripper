using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

[SuppressMessage("ReSharper", "IdentifierTypo")]
[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct MishBlock
{
  public UInt32 Signature;
  public UInt32 Version;
  public UInt64 SectorNumber;
  public UInt64 SectorCount;

  public UInt64 DataOffset;
  public UInt32 BuffersNeeded;
  public UInt32 BlockDescriptors;

  public UInt32 reserved1;
  public UInt32 reserved2;
  public UInt32 reserved3;
  public UInt32 reserved4;
  public UInt32 reserved5;
  public UInt32 reserved6;

  public fixed byte checksum[136]; // Using the existing UDIFChecksum definition from your sample

  public UInt32 NumberOfBlockChunks;

  public BLKXChunkEntry[] BlkxChunkEntries;

  internal MishBlock(BinaryReader reader)
  {
    Signature = reader.ReadUInt32();
    if (MemoryUtil.GetBeU4(Signature) != 1835627368)
      throw new FormatException("Wrong Mish header");

    Version = reader.ReadUInt32();
    SectorNumber = reader.ReadUInt64();
    SectorCount = reader.ReadUInt64();

    DataOffset = reader.ReadUInt64();
    BuffersNeeded = reader.ReadUInt32();
    BlockDescriptors = reader.ReadUInt32();

    reserved1 = reader.ReadUInt32();
    reserved2 = reader.ReadUInt32();
    reserved3 = reader.ReadUInt32();
    reserved4 = reader.ReadUInt32();
    reserved5 = reader.ReadUInt32();
    reserved6 = reader.ReadUInt32();

    var checksumBytes = reader.ReadBytes(136);
    for (int i = 0; i < checksumBytes.Length; i++)
      checksum[i] = checksumBytes[i];

    NumberOfBlockChunks = reader.ReadUInt32();
    BlkxChunkEntries = new BLKXChunkEntry[MemoryUtil.GetBeU4(NumberOfBlockChunks)];
    for (int i = 0; i < MemoryUtil.GetBeU4(NumberOfBlockChunks); i++)
    {
      var bytes = reader.ReadBytes(sizeof(BLKXChunkEntry));
      using MemoryStream ms = new MemoryStream(bytes);

      BLKXChunkEntry bufferEntry;
      StreamUtil.ReadBytes(ms, (byte*)&bufferEntry, sizeof(BLKXChunkEntry));

      BlkxChunkEntries[i] = bufferEntry;
    }
  }
}