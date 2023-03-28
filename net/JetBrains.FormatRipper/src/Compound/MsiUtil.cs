using System.Text;

namespace JetBrains.FormatRipper.Compound
{
  public static class MsiUtil
  {
    private static char MsiBase64Encode(byte v)
    {
      // 0-0x3F converted to '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'
      // all other values higher as 0x3F converted also to '_'

      // 0-9 (0x0-0x9) -> '0123456789'
      if (v < 10)
        return (char)(v + '0');

      // 10-35 (0xA-0x23) -> 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      if (v < 10 + 26)
        return (char)(v - 10 + 'A');

      // 36-61 (0x24-0x3D) -> 'abcdefghijklmnopqrstuvwxyz'
      if (v < 10 + 26 + 26)
        return (char)(v - 10 - 26 + 'a');

      // 62 (0x3E) -> '.'
      if (v == 10 + 26 + 26)
        return '.';

      // 63-0xFFFFFFFF (0x3F-0xFFFFFFFF) -> '_'
      return '_';
    }

    public static string MsiDecodeStreamName(string str)
    {
      // See https://stackoverflow.com/questions/9734978/view-msi-strings-in-binary

      var sb = new StringBuilder(str.Length);
      foreach (var ch in str)
        if (ch >= 0x3800 && ch < 0x4840)
        {
          // A part of Unicode characters used with CJK Unified Ideographs Extension A. (added with Unicode 3.0) used by
          // Windows Installer for encoding one or two ANSI characters. This subset of Unicode characters are not currently
          // used nether in "MS PMincho" or "MS PGothic" font nor in "Arial Unicode MS"
          if (ch >= 0x4800)
            // 0x4800 - 0x483F, only one character can be decoded
            sb.Append(MsiBase64Encode((byte)(ch - 0x4800)));
          else
          {
            // 0x3800 - 0x383F, the value contains two characters
            var v = (ushort)(ch - 0x3800);
            sb.Append(MsiBase64Encode((byte)(v & 0x3f)));
            sb.Append(MsiBase64Encode((byte)((v >> 6) & 0x3f)));
          }
        }
        else
          sb.Append(ch); // All characters lower as 0x3800 or higher or equal to 0x4840 will be saved without any decoding

      return sb.ToString();
    }
  }
}