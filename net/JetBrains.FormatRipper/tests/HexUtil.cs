using System;

namespace JetBrains.FormatRipper.Tests
{
  internal static class HexUtil
  {
    internal static string ConvertToHexString(byte[] data) => BitConverter.ToString(data).Replace("-", "");
  }
}