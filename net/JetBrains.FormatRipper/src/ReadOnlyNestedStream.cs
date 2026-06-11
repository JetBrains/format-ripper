using System;
using System.IO;

namespace JetBrains.FormatRipper
{
  public sealed class ReadOnlyNestedStream : Stream
  {
    private readonly Stream myStream;
    private readonly long myOffset;
    private readonly long myLength;
    private long myPosition;

    public ReadOnlyNestedStream(Stream stream, long offset, long length)
    {
      if (!stream.CanRead)
        throw new ArgumentException("Stream must be readable", nameof(stream));
      if (!stream.CanSeek)
        throw new ArgumentException("Stream must be seekable", nameof(stream));
      if (offset < 0)
        throw new ArgumentOutOfRangeException(nameof(offset));
      if (length < 0)
        throw new ArgumentOutOfRangeException(nameof(length));
      if (stream.Length < offset + length)
        throw new ArgumentException("Stream length is less than the requested length", nameof(stream));
      myStream = stream;
      myOffset = offset;
      myLength = length;
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
      var remaining = myLength - myPosition;
      if (remaining <= 0) return 0;
      count = (int)Math.Min(count, remaining);
      myStream.Position = myOffset + myPosition;
      var read = myStream.Read(buffer, offset, count);
      myPosition += read;
      return read;
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
