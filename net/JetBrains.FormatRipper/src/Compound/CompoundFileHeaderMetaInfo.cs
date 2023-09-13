using System.Collections.Generic;
using JetBrains.FormatRipper.Compound.Impl;

namespace JetBrains.FormatRipper.Compound;

public class CompoundFileHeaderMetaInfo
{
  public readonly List<uint> SectFat;
  public readonly List<uint> Fat;
  public readonly List<uint> MiniFat;
  public readonly CompoundFileHeaderData Header;

  public static CompoundFileHeaderMetaInfo GetInstance(
    CompoundFileHeader header,
    List<uint>? sectFat = null,
    List<uint>? fat = null,
    List<uint>? miniFat = null)
    =>
      new(CompoundFileHeaderData.GetInstance(header), sectFat ?? new List<uint>(),
        fat ?? new List<uint>(), miniFat ?? new List<uint>());

  public CompoundFileHeaderMetaInfo(CompoundFileHeaderData header, List<uint> sectFat, List<uint> fat,
    List<uint> miniFat)
  {
    SectFat = sectFat;
    Fat = fat;
    MiniFat = miniFat;
    Header = header;
  }
}