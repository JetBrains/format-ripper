using System.Collections.Generic;

namespace JetBrains.FormatRipper.Dmg;

public class BLKXEntry
{
  public readonly string Attributes;
  public readonly string CFName;
  public readonly MishBlock Data;
  public readonly List<byte[]> CompressedChunks = new List<byte[]>();
  public readonly string ID;
  public readonly string Name;

  public BLKXEntry(string attributes, string cfName, MishBlock data, string id, string name)
  {
    Attributes = attributes;
    CFName = cfName;
    Data = data;
    ID = id;
    Name = name;
  }
}