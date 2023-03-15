using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace JetBrains.FormatRipper
{
  public sealed class ComputeHashInfo
  {
    public delegate void SubmitDelegate(byte[] buffer, int index, int count);

    public readonly long Offset;
    public readonly IEnumerable<StreamRange> OrderedIncludeRanges;
    public readonly int ZeroPadding;

    internal ComputeHashInfo(long offset, IEnumerable<StreamRange> orderedIncludeRanges, int zeroPadding)
    {
      if (offset < 0)
        throw new ArgumentOutOfRangeException(nameof(offset));
      if (zeroPadding < 0)
        throw new ArgumentOutOfRangeException(nameof(zeroPadding));
      Offset = offset;
      OrderedIncludeRanges = orderedIncludeRanges;
      ZeroPadding = zeroPadding;
    }

    public void WalkOnHashRanges(Stream stream, SubmitDelegate submit)
    {
      foreach (var range in OrderedIncludeRanges)
      {
        stream.Position = checked(range.Position + Offset);
        var buffer = new byte[1024 * 1024];
        for (var size = range.Size; size > 0;)
        {
          var maxLength = size > buffer.Length ? buffer.Length : (int)size;
          var read = stream.Read(buffer, 0, maxLength);
          if (read == 0)
            throw new EndOfStreamException();
          submit(buffer, 0, read);
          size -= read;
        }
      }

      if (ZeroPadding > 0)
        submit(new byte[ZeroPadding], 0, ZeroPadding);
    }

    public override string ToString()
    {
      var sb = new StringBuilder()
        .Append(Offset.ToString("X")).Append(';')
        .Append(ZeroPadding.ToString("X")).Append(';');
      var isFirst = true;
      foreach (var range in OrderedIncludeRanges)
      {
        if (isFirst)
          isFirst = false;
        else
          sb.Append(',');
        sb.Append(range);
      }

      return sb.ToString();
    }
  }
}