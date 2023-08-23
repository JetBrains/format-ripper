using System.Collections.Generic;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class CodeSignatureInfo
{
  public uint magic;
  public uint length;
  public long superBlobStart;
  public int superBlobCount;
  public readonly List<Blob> blobs = new List<Blob>();

  public byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(MemoryUtil.GetBeU4(magic)),
      MemoryUtil.ToByteArray(MemoryUtil.GetBeU4(length)),
      MemoryUtil.ToByteArray(MemoryUtil.GetBeU4((uint)blobs.Count)),
      BlobsToByteArray()
    );

  private byte[] BlobsToByteArray()
  {
    byte[] result = new byte[0];
    foreach (var blob in blobs)
    {
      result = MemoryUtil.ArrayMerge(
        result,
        MemoryUtil.ToByteArray(MemoryUtil.GetBeU4(blob.type)),
        MemoryUtil.ToByteArray(MemoryUtil.GetBeU4(blob.offset))
      );
    }

    return result;
  }
}