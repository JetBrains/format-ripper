using System;
using System.Collections.Generic;
using System.Text;
using JetBrains.FormatRipper.Compound.Impl;

namespace JetBrains.FormatRipper.Compound;

public class CompoundFileMetadata
{
  public long FileSize { get; set; }
  private CompoundFileHeaderMetaInfo CompoundFileHeaderMetaInfo { get; set; }
  private List<CompoundFileDirectoryEntry> Entries { get; set; }
  private List<KeyValuePair<string, byte[]>> SpecialEntries { get; set; }
  private List<KeyValuePair<int, byte[]>> SpecialSegments { get; set; }
  private byte[] DigitalSignatureExData { get; set; } // Nullable
  private int MiniStreamStartSector { get; set; }

  public void aboba()
  {

  }

  public CompoundFileMetadata(int a)
  {
    aboba();
  }

  public static CompoundFileMetadata create()
  {
    return new CompoundFileMetadata(1);
  }

  public static string[] specialValues =
  {
    new(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 59, 242, 67, 56, 68, 177, 69 })),
    new(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 63, 119, 69, 108, 68, 106, 62, 178, 68, 47, 72 }))
  };
}