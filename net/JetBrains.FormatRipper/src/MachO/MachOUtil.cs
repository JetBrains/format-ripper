using System;

namespace JetBrains.FormatRipper.MachO
{
  public static class MachOUtil
  {
    public static bool NeedSwap(MachOFile.Endian endian) => BitConverter.IsLittleEndian != endian switch
      {
        MachOFile.Endian.Little => true,
        MachOFile.Endian.Big => false,
        _ => throw new ArgumentOutOfRangeException(nameof(endian), endian, null)
      };
  }
}