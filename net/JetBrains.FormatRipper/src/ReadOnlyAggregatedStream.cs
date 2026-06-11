using System;
using System.Collections.Generic;
using System.IO;

namespace JetBrains.FormatRipper
{
  public sealed class ReadOnlyAggregatedStream : Stream
  {
    private readonly Stream[] myStreams;
    private readonly long[] myOffsets;
    private readonly long myLength;
    private long myPosition;

    public ReadOnlyAggregatedStream(params Stream[] streams)
    {
      foreach (var stream in streams)
      {
        if (!stream.CanRead)
          throw new ArgumentException("All streams must be readable", nameof(streams));
        if (!stream.CanSeek)
          throw new ArgumentException("All streams must be seekable", nameof(streams));
      }
      var filteredStreams = new List<Stream>(streams.Length);
      var filteredOffsets = new List<long>(streams.Length);
      var offset = 0L;
      foreach (var stream in streams)
      {
        var length = stream.Length;
        if (length <= 0)
          continue;
        filteredStreams.Add(stream);
        filteredOffsets.Add(offset);
        offset += length;
      }
      myStreams = filteredStreams.ToArray();
      myOffsets = filteredOffsets.ToArray();
      myLength = offset;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => myLength;

    public override long Position
    {
      get => myPosition;
      set
      {
        if (value < 0)
          throw new ArgumentOutOfRangeException(nameof(value));
        if (myLength < value)
          throw new ArgumentOutOfRangeException(nameof(value));
        myPosition = value;
      }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
      if (offset < 0)
        throw new ArgumentOutOfRangeException(nameof(offset));
      if (count < 0)
        throw new ArgumentOutOfRangeException(nameof(count));
      var totalRead = 0;
      while (totalRead < count)
      {
        var streamIndex = FindStreamIndex(myPosition);
        var streamOffset = myPosition - myOffsets[streamIndex];
        var stream = myStreams[streamIndex];
        var streamRemaining = stream.Length - streamOffset;
        var toRead = (int)Math.Min(count - totalRead, streamRemaining);
        stream.Position = streamOffset;
        var read = stream.Read(buffer, offset + totalRead, toRead);
        if (read == 0)
          break;
        myPosition += read;
        totalRead += read;
      }
      return totalRead;

      int FindStreamIndex(long position)
      {
        var index = Array.BinarySearch(myOffsets, position);
        return index < 0 ? ~index - 1 : index;
      }
    }

    public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
      {
        SeekOrigin.Begin => offset,
        SeekOrigin.Current => myPosition + offset,
        SeekOrigin.End => myLength + offset,
        _ => throw new ArgumentOutOfRangeException(nameof(origin))
      };

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() => throw new NotSupportedException();
  }
}
