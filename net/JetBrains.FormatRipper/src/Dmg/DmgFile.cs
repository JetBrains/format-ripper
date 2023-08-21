using System;
using System.IO;
using JetBrains.FormatRipper.Impl;

namespace JetBrains.FormatRipper.Dmg
{
  public sealed class DmgFile
  {
    static byte[] epxectedSignature = new byte[] { 0x6b, 0x6f, 0x6c, 0x79 };

    public static unsafe bool Is(Stream stream)
    {
      stream.Position = stream.Length - 512;
      UDIFResourceFile header;
      StreamUtil.ReadBytes(stream, (byte*)&header, sizeof(UDIFResourceFile));
      return MemoryUtil.ArraysEqual(header.udifSignature, 4, epxectedSignature);
    }
  }
}