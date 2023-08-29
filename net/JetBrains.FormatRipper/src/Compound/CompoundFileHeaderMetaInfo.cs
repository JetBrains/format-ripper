using System;
using System.Collections.Generic;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Compound.Impl;

namespace JetBrains.FormatRipper.Compound;

public class CompoundFileHeaderMetaInfo
{
  public List<uint> SectFat { get; set; }
  public List<uint> Fat { get; set; }
  public List<uint> MiniFat { get; set; }
  public CompoundFileHeaderData Header { get; }

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