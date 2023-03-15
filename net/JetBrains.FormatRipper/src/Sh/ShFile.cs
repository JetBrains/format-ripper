using System.IO;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Sh
{
  public static class ShFile
  {
    public static bool Is(Stream stream)
    {
      stream.Position = 0;
      var header = StreamUtil.ReadBytes(stream, 2);
      return header[0] == (byte)'#' &&
             header[1] == (byte)'!';
    }
  }
}