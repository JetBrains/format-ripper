using System;

namespace JetBrains.FormatRipper
{
  public readonly struct StreamRange
  {
    public readonly long Position;
    public readonly long Size;

    internal StreamRange(long position, long size)
    {
      if (position < 0)
        throw new ArgumentOutOfRangeException(nameof(position), position, null);
      if (size < 0)
        throw new ArgumentOutOfRangeException(nameof(size), size, null);
      Position = position;
      Size = size;
    }

    public override string ToString() => $"[{Position:X}:{Size:X}]";
  }
}