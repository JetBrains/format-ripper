using System.IO;

namespace JetBrains.FormatRipper.Impl
{
  public static class StreamUtil
  {
    private static void Read(Stream stream, byte[] buffer, int index, int size)
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

    public static byte[] ReadBytes(Stream stream, int size)
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
  }
}