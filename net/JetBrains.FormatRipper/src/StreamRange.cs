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
        throw new ArgumentOutOfRangeException(nameof(position));
      if (size < 0)
        throw new ArgumentOutOfRangeException(nameof(size));
      Position = position;
      Size = size;
    }

    public override string ToString() => $"[{Position:X}:{Size:X}]";
  }
}