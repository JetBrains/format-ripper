using System.Collections;
using JetBrains.FormatRipper.Compound;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.Msi;

[JsonObject(MemberSerialization.OptIn)]
public class MsiFileMetaInfo : IFileMetaInfo
{
  [JsonProperty("FileSize")] public long FileSize { get; set; }

  [JsonProperty("CompoundFileHeaderMetaInfo")]
  private CompoundFileHeaderMetaInfo CompoundFileHeaderMetaInfo { get; set; }

  [JsonProperty("Entries")] private List<CompoundFile.DirectoryEntry> Entries { get; set; }
  [JsonProperty("SpecialEntries")] private List<KeyValuePair<string, byte[]>> SpecialEntries { get; set; }
  [JsonProperty("SpecialSegments")] private List<KeyValuePair<long, byte[]>> SpecialSegments { get; set; }

  [JsonProperty("DigitalSignatureExData")]
  private byte[] DigitalSignatureExData { get; set; } // Nullable

  [JsonProperty("MiniStreamStartSector")]
  private int MiniStreamStartSector { get; set; }

  [JsonConstructor]
  public MsiFileMetaInfo(long fileSize, CompoundFileHeaderMetaInfo compoundFileHeaderMetaInfo,
    List<CompoundFile.DirectoryEntry> entries, List<KeyValuePair<string, byte[]>> specialEntries,
    List<KeyValuePair<long, byte[]>> specialSegments, byte[] digitalSignatureExData, int miniStreamStartSector)
  {
    FileSize = fileSize;
    CompoundFileHeaderMetaInfo = compoundFileHeaderMetaInfo;
    Entries = entries;
    SpecialEntries = specialEntries;
    SpecialSegments = specialSegments;
    DigitalSignatureExData = digitalSignatureExData;
    MiniStreamStartSector = miniStreamStartSector;
  }

  public void ModifyFile(Stream stream, byte[] signature)
  {
    var unsignedFile = CompoundFile.Parse(stream, CompoundFile.Mode.SIGNATURE_DATA);
    var unsignedEntries = unsignedFile.GetEntries();
    var unsignedEntriesMap = new Hashtable();
    foreach (var keyValuePair in unsignedEntries)
    {
      if (unsignedEntriesMap.Contains(keyValuePair.Key.Name.Trim(new[] { '' })))
        continue;
      unsignedEntriesMap.Add(keyValuePair.Key.Name.Trim(new[] { '' }), keyValuePair.Value);
    }

    var unsignedRoot = unsignedEntries.Find(
      entry => entry.Key.Name.Trim(new[] { '' }).Equals("Root Entry")
    );

    var startSect = unsignedRoot.Key.StartingSectorLocation;

    unsignedFile.PutEntries(unsignedEntries, (uint)startSect, wipe: true);

    unsignedFile = new CompoundFile(CompoundFileHeaderMetaInfo, stream);

    var specialEntriesDataMap = new Hashtable
    {
      { "MsiDigitalSignatureEx", DigitalSignatureExData },
      { "DigitalSignature", signature }
    };
    foreach (var kv in SpecialEntries)
    {
      specialEntriesDataMap.Add(kv.Key, kv.Value);
    }

    unsignedFile.PutEntries(
      Entries.Select(entry =>
        {
          var trimmedName = entry.Name.Trim(new[] { '' });
          if (specialEntriesDataMap.Contains(trimmedName))
            return new KeyValuePair<CompoundFile.DirectoryEntry, byte[]?>(entry,
              (byte[])specialEntriesDataMap[trimmedName]!);
          else
            return new KeyValuePair<CompoundFile.DirectoryEntry, byte[]?>(entry,
              (byte[])unsignedEntriesMap[trimmedName]!);
        }
      ).ToList()!, (uint)MiniStreamStartSector
    );
    //
    foreach (var segment in SpecialSegments)
    {
      stream.Position = segment.Key;
      stream.Write(segment.Value, 0, segment.Value.Length);
    }

    //
    if (FileSize < stream.Length)
    {
      stream.SetLength(FileSize);
    }
    else if (FileSize > stream.Length)
    {
      var diff = FileSize - stream.Length;
      stream.Write(new byte[diff], 0, (int)diff);
    }
  }
}