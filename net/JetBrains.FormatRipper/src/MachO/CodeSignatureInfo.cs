using System.Collections.Generic;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class CodeSignatureInfo
{
  public uint Magic = 0;
  public uint Length = 0;
  public long SuperBlobStart = 0;
  public int SuperBlobCount = 0;
  public readonly List<Blob> Blobs = new List<Blob>();

  public byte[] ToByteArray() => MemoryUtil.ArrayMerge(
    MemoryUtil.ToByteArray(Magic, true),
    MemoryUtil.ToByteArray(Length, true),
    MemoryUtil.ToByteArray(Blobs.Count, true),
    BlobsToByteArray()
  );

  private byte[] BlobsToByteArray()
  {
    byte[] result = new byte[0];
    foreach (var blob in Blobs)
    {
      result = MemoryUtil.ArrayMerge(result,
        MemoryUtil.ToByteArray(blob.Type, true),
        MemoryUtil.ToByteArray(blob.Offset, true));
    }

    return result;
  }
}