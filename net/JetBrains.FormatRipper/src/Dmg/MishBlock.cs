using System;
using System.Collections.Generic;
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

  private static byte[] expectedSignature = new byte[] { 0x6D, 0x69, 0x73, 0x68 };

  internal MishBlock(BinaryReader reader)
  {
    Signature = reader.ReadUInt32();

    byte[] signatureBytes = BitConverter.GetBytes(MemoryUtil.GetLeU4(Signature));

    fixed (byte* p = signatureBytes)
    {
      if (!MemoryUtil.ArraysEqual(p, expectedSignature.Length, expectedSignature))
        throw new FormatException("Wrong Mish header: " + BitConverter.ToString(signatureBytes));
    }

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

    // FIXME: I am not sure why, but it only works if we swap in both LE and BE.
    BlkxChunkEntries = new BLKXChunkEntry[MemoryUtil.SwapU4(NumberOfBlockChunks)];

    for (int i = 0; i < MemoryUtil.SwapU4(NumberOfBlockChunks); i++)
    {
      var bytes = reader.ReadBytes(sizeof(BLKXChunkEntry));
      if (bytes.Length != sizeof(BLKXChunkEntry))
      {
        throw new FormatException("Couldn't read full BLKXChunk");
      }

      using MemoryStream ms = new MemoryStream(bytes);

      BLKXChunkEntry bufferEntry;
      StreamUtil.ReadBytes(ms, (byte*)&bufferEntry, sizeof(BLKXChunkEntry));

      BlkxChunkEntries[i] = bufferEntry;
    }
  }
}