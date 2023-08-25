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

  public CodeSignatureInfo(){}

  public CodeSignatureInfo(uint magic, uint length, long superBlobStart, int superBlobCount, List<Blob> blobs)
  {
    this.magic = magic;
    this.length = length;
    this.superBlobStart = superBlobStart;
    this.superBlobCount = superBlobCount;
    this.blobs = blobs;
  }

  public byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
      MemoryUtil.ToByteArray(magic, true),
      MemoryUtil.ToByteArray(length, true),
      MemoryUtil.ToByteArray(blobs.Count, true),
      BlobsToByteArray()
    );

  private byte[] BlobsToByteArray()
  {
    byte[] result = new byte[0];
    foreach (var blob in blobs)
    {
      result = MemoryUtil.ArrayMerge(
        result,
        MemoryUtil.ToByteArray(blob.type, true),
        MemoryUtil.ToByteArray(blob.offset, true)
      );
    }

    return result;
  }
}