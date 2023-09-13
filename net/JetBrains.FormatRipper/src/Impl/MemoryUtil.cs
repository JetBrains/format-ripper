using System;

namespace JetBrains.FormatRipper.Impl
{
  internal static class MemoryUtil
  {
    internal static ushort SwapU2(ushort v) => (ushort)((v << 8) | (v >> 8));

    internal static uint SwapU4(uint v)
    {
      v = ((v << 8) & 0xFF00FF00u) | ((v >> 8) & 0x00FF00FFu);
      return (v << 16) | (v >> 16);
    }

    internal static ulong SwapU8(ulong v)
    {
      v = ((v << 8) & 0xFF00FF00FF00FF00ul) | ((v >> 8) & 0x00FF00FF00FF00FFul);
      v = ((v << 16) & 0xFFFF0000FFFF0000ul) | ((v >> 16) & 0x0000FFFF0000FFFFul);
      return (v << 32) | (v >> 32);
    }

    internal static unsafe Guid SwapGuid(Guid v)
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

    internal static ushort GetLeU2(ushort v) => BitConverter.IsLittleEndian ? v : SwapU2(v);
    internal static uint GetLeU4(uint v) => BitConverter.IsLittleEndian ? v : SwapU4(v);
    internal static ulong GetLeU8(ulong v) => BitConverter.IsLittleEndian ? v : SwapU8(v);
    internal static Guid GetLeGuid(Guid v) => BitConverter.IsLittleEndian ? v : SwapGuid(v);

    internal static ushort GetBeU2(ushort v) => BitConverter.IsLittleEndian ? SwapU2(v) : v;
    internal static uint GetBeU4(uint v) => BitConverter.IsLittleEndian ? SwapU4(v) : v;
    internal static ulong GetBeU8(ulong v) => BitConverter.IsLittleEndian ? SwapU8(v) : v;
    internal static Guid GetBeGuid(Guid v) => BitConverter.IsLittleEndian ? SwapGuid(v) : v;

    internal static unsafe void CopyBytes(byte* src, byte* dst, int size)
    {
      while (size-- > 0)
        *dst++ = *src++;
    }

    internal static unsafe byte[] CopyBytes(byte* buf, int size)
    {
      var res = new byte[size];
      fixed (byte* ptr = res)
        CopyBytes(buf, ptr, size);
      return res;
    }

    internal static int GetAsciiStringZSize(byte[] buf)
    {
      var size = 0;
      while (size < buf.Length && buf[size] != 0)
        ++size;
      return size;
    }

    internal static unsafe bool ArraysEqual(byte* array1, int size1, byte[]? array2)
    {
      if (array1 == null || array2 == null)
        return false;
      if (size1 != array2.Length)
        return false;
      for (var i = 0; i < size1; i++)
        if (array1[i] != array2[i])
          return false;
      return true;
    }

    internal static T[] ArrayMerge<T>(T[] array1, params T[] array2)
    {
      var res = new T[array1.Length + array2.Length];
      Array.Copy(array1, res, array1.Length);
      Array.Copy(array2, 0, res, array1.Length, array2.Length);
      return res;
    }

    internal static T[] ArrayMerge<T>(params T[][] arrays)
    {
      var totalLength = 0;
      foreach (var array in arrays)
        totalLength += array.Length;

      var res = new T[totalLength];
      var offset = 0;

      foreach (var array in arrays)
      {
        Array.Copy(array, 0, res, offset, array.Length);
        offset += array.Length;
      }

      return res;
    }

    internal static byte[] ToByteArray(int value, bool isBe = false)
    {
      byte[] bytes = BitConverter.GetBytes(value);

      if (BitConverter.IsLittleEndian == isBe)
      {
        Array.Reverse(bytes);
      }

      return bytes;
    }

    internal static byte[] ToByteArray(long value, bool isBe = false)
    {
      byte[] bytes = BitConverter.GetBytes(value);

      if (BitConverter.IsLittleEndian == isBe)
      {
        Array.Reverse(bytes);
      }

      return bytes;
    }

    internal static byte[] ToByteArray(uint value, bool isBe = false)
    {
      byte[] bytes = BitConverter.GetBytes(value);

      if (BitConverter.IsLittleEndian == isBe)
      {
        Array.Reverse(bytes);
      }

      return bytes;
    }

    internal static byte[] ToByteArray(ushort value, bool isBe = false)
    {
      byte[] bytes = BitConverter.GetBytes(value);

      if (BitConverter.IsLittleEndian == isBe)
      {
        Array.Reverse(bytes);
      }

      return bytes;
    }

    internal static byte[] SliceArray(byte[] source, int offset, int size)
    {
      var result = new byte[size];
      for (int i = 0; i < size; i++)
      {
        result[i] = source[offset + i];
      }

      return result;
    }
  }
}