using System;

namespace JetBrains.FormatRipper
{
  public static class EndianUtil
  {
    public static ushort SwapU2(ushort v) => (ushort)((v << 8) | (v >> 8));

    public static uint SwapU4(uint v)
    {
      v = ((v << 8) & 0xFF00FF00u) | ((v >> 8) & 0x00FF00FFu);
      return (v << 16) | (v >> 16);
    }

    public static ulong SwapU8(ulong v)
    {
      v = ((v << 8) & 0xFF00FF00FF00FF00ul) | ((v >> 8) & 0x00FF00FF00FF00FFul);
      v = ((v << 16) & 0xFFFF0000FFFF0000ul) | ((v >> 16) & 0x0000FFFF0000FFFFul);
      return (v << 32) | (v >> 32);
    }

    public static unsafe Guid SwapGuid(Guid v)
    {
      Guid res;
      var src = (byte*)&v;
      var dst = (byte*)&res;

      dst[0] = src[3];
      dst[1] = src[2];
      dst[2] = src[1];
      dst[3] = src[0];

      dst[4] = src[5];
      dst[5] = src[4];

      dst[6] = src[7];
      dst[7] = src[6];

      for (var n = 8; n < 16; ++n)
        dst[n] = src[n];

      return res;
    }

    public static ushort GetLeU2(ushort v) => BitConverter.IsLittleEndian ? v : SwapU2(v);
    public static uint GetLeU4(uint v) => BitConverter.IsLittleEndian ? v : SwapU4(v);
    public static ulong GetLeU8(ulong v) => BitConverter.IsLittleEndian ? v : SwapU8(v);
    public static Guid GetLeGuid(Guid v) => BitConverter.IsLittleEndian ? v : SwapGuid(v);
    public static ushort GetBeU2(ushort v) => BitConverter.IsLittleEndian ? SwapU2(v) : v;
    public static uint GetBeU4(uint v) => BitConverter.IsLittleEndian ? SwapU4(v) : v;
    public static ulong GetBeU8(ulong v) => BitConverter.IsLittleEndian ? SwapU8(v) : v;
    public static Guid GetBeGuid(Guid v) => BitConverter.IsLittleEndian ? SwapGuid(v) : v;
  }
}