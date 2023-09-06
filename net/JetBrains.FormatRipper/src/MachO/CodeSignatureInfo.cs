using System.Collections.Generic;
using JetBrains.FormatRipper.Dmg;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.MachO;

public class CodeSignatureInfo
{
  public uint Magic { get; set; } = 0;
  public uint Length { get; set; } = 0;
  public long SuperBlobStart { get; set; } = 0;
  public int SuperBlobCount { get; set; } = 0;
  public List<Blob> Blobs { get; set; } = new List<Blob>();

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
        MemoryUtil.ToByteArray(blob.type, true),
        MemoryUtil.ToByteArray(blob.offset, true));
    }

    return result;
  }
}