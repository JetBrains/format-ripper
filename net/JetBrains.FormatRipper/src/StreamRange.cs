using System;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper
{
  public readonly struct StreamRange
  {
    public readonly long Position;
    public readonly long Size;

    public StreamRange(long position, long size)
    {
      if (position < 0)
        throw new ArgumentOutOfRangeException(nameof(position), position, null);
      if (size < 0)
        throw new ArgumentOutOfRangeException(nameof(size), size, null);
      Position = position;
      Size = size;
    }

    public override string ToString() => $"[{Position:X}:{Size:X}]";

    public byte[] ToByteArray(bool isBe = false) =>
      MemoryUtil.ArrayMerge(
        MemoryUtil.ToByteArray(Position, isBe: isBe),
        MemoryUtil.ToByteArray(Size, isBe: isBe)
      );
  }
}