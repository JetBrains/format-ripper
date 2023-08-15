using System.Collections.Generic;
using JetBrains.FormatRipper.Compound;
using JetBrains.FormatRipper.Compound.Impl;

namespace JetBrains.FormatRipper.Compound;

public class CompoundFileHeaderMetaInfo
{
  public CompoundFileHeader Header { get; set; }
  public List<uint> SectFat { get; set; }
  public List<uint> Fat { get; set; }
  public List<uint> MiniFat { get; set; }

  public CompoundFileHeaderMetaInfo(
    CompoundFileHeader header,
    List<uint>? sectFat = null,
    List<uint>? fat = null,
    List<uint>? miniFat = null)
  {
    Header = header;
    SectFat = sectFat ?? new List<uint>();
    Fat = fat ?? new List<uint>();
    MiniFat = miniFat ?? new List<uint>();
  }
}