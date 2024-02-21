using System;
using System.IO;

namespace JetBrains.FormatRipper.Impl
{
  internal static class StreamUtil
  {
    internal static void Read(Stream stream, byte[] buffer, int index, int size)
    {
      while (size > 0)
      {
        var read = stream.Read(buffer, index, size);
        if (read == 0)
          throw new EndOfStreamException();
        index += read;
        size -= read;
      }
    }

    internal static byte[] ReadBytes(Stream stream, int size)
    {
      var buffer = new byte[size];
      Read(stream, buffer, 0, buffer.Length);
      return buffer;
    }

    internal static unsafe void ReadBytes(Stream stream, byte* dst, int size)
    {
      // Note(ww898): It is strongly required to avoid crashes because expression `v = *(V*)b` makes a cast for type which can require the bigger alignment then the alignment in the GC allocations.
      fixed (byte* buf = ReadBytes(stream, size))
        MemoryUtil.CopyBytes(buf, dst, size);
    }

    internal static unsafe void WriteBytes(Stream stream, byte* src, int size)
    {
      byte[] buffer = MemoryUtil.CopyBytes(src, size);
      stream.Write(buffer, 0, buffer.Length);
    }

    internal static void CopyBytes(Stream sourceStream, Stream destinationStream, long bytesToCopy, int maxChunk = 1024 * 1024)
    {
      byte[] buffer = new byte[maxChunk];

      while (bytesToCopy > 0)
      {
        long chunk = Math.Min(maxChunk, bytesToCopy);

        int actualRead = sourceStream.Read(buffer, 0, (int)chunk);

        if (actualRead == 0)
          throw new IOException($"Error reading from the source stream. Stream position: {sourceStream.Position}, stream length: {sourceStream.Length}, attempted to read {chunk} bytes");

        destinationStream.Write(buffer, 0, actualRead);

        bytesToCopy -= actualRead;
      }
    }
  }
}