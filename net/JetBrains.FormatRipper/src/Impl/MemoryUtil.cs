using System;

namespace JetBrains.FormatRipper.Impl
{
  internal static class MemoryUtil
  {
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
  }
}