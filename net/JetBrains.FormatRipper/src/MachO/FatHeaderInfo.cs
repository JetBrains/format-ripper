using System.Collections.Generic;
using JetBrains.FormatRipper.Impl;
using JetBrains.FormatRipper.MachO.Impl;

namespace JetBrains.FormatRipper.MachO;

public class FatHeaderInfo
{
  public readonly uint Magic;
  public readonly bool IsBe;
  public readonly uint FatArchSize;
  public readonly List<FatArchInfo> FatArchInfos;

  public FatHeaderInfo(uint magic, bool isBe, uint fatArchSize, List<FatArchInfo> fatArchInfos)
  {
    Magic = magic;
    IsBe = isBe;
    FatArchSize = fatArchSize;
    FatArchInfos = fatArchInfos;
  }

  public byte[] ToByteArray() => MemoryUtil.ArrayMerge(
    MemoryUtil.ToByteArray(Magic),
    MemoryUtil.ToByteArray(FatArchSize, IsBe),
    InfosToByteArray()
  );

  private byte[] InfosToByteArray()
  {
    byte[] res = new byte[0];
    foreach (var fatArchInfo in FatArchInfos)
    {
      res = MemoryUtil.ArrayMerge(res, fatArchInfo.ToByteArray(IsBe));
    }

    return res;
  }
}