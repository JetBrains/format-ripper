using System.Collections.Generic;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg;

public class CodeSignatureInfo
{
  public uint Magic;
  public uint Length;
  public long SuperBlobStart;
  public int SuperBlobCount;
  public readonly List<Blob> Blobs = new List<Blob>();

  public CodeSignatureInfo(){}

  public CodeSignatureInfo(uint magic, uint length, long superBlobStart, int superBlobCount, List<Blob> blobs)
  {
    Magic = magic;
    Length = length;
    SuperBlobStart = superBlobStart;
    SuperBlobCount = superBlobCount;
    Blobs = blobs;
  }

  public byte[] ToByteArray() =>
    MemoryUtil.ArrayMerge(
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
      result = MemoryUtil.ArrayMerge(
        result,
        MemoryUtil.ToByteArray(blob.Type, true),
        MemoryUtil.ToByteArray(blob.Offset, true)
      );
    }

    return result;
  }
}