using System;
using System.IO;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Sh
{
  public sealed class ShFile
  {
    public static ShFile Parse(Stream stream)
    {
      stream.Position = 0;
      var header = StreamUtil.ReadBytes(stream, 2);
      if (header[0] != (byte)'#' ||
          header[1] != (byte)'!')
        throw new FormatException("Invalid header");
      return new ShFile();
    }
  }
}