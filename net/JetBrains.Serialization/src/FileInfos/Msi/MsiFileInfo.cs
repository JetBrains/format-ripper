using System.Text;
using JetBrains.FormatRipper.Compound;
using JetBrains.SignatureVerifier.Crypt;
using Newtonsoft.Json;

namespace JetBrains.Serialization.FileInfos.Msi;

[JsonObject(MemberSerialization.OptIn)]
public class MsiFileInfo : FileInfo
{
  [JsonProperty("fileMetaInfo")] public override IFileMetaInfo FileMetaInfo { get; }

  [JsonProperty("signedDataInfo")] public override SignedDataInfo SignedDataInfo { get; }

  [JsonConstructor]
  public MsiFileInfo(IFileMetaInfo fileMetaInfo, SignedDataInfo signedDataInfo)
  {
    FileMetaInfo = fileMetaInfo;
    SignedDataInfo = signedDataInfo;
  }

  public MsiFileInfo(CompoundFile compoundFile)
  {
    var signatureData = compoundFile.SignatureData;
    var signedMessage = SignedMessage.CreateInstance(signatureData);
    SignedDataInfo = new SignedDataInfo(signedMessage.SignedData);

    List<KeyValuePair<long, long>> visitedSegments = new();
    List<KeyValuePair<long, long>> rootSegments = new();

    var entries = compoundFile.GetEntries(visitedSegments, rootSegments);

    var mergedSegments = MergeSegments(visitedSegments);
    var mergedRootSegment = MergeSegments(rootSegments)[0];


    var specialEntries = entries.FindAll(
      entry =>
        _specialValues.Contains(entry.Key.Name.Trim(new[] { '' }))
    ).Select(kv => new KeyValuePair<string, byte[]>(kv.Key.Name, kv.Value)).ToList();
    var rootEntry = entries.Find(
      entry => entry.Key.Name.Trim(new[] { '' }).Equals("Root Entry")
    );


    var specialSegments = FindGaps(mergedRootSegment.Key, mergedRootSegment.Value,
      mergedSegments.FindAll(it => it.Key >= mergedRootSegment.Key && it.Value <= mergedRootSegment.Value)
    ).Select(range =>
      new KeyValuePair<long, byte[]>(range.Key,
        SliceArray(rootEntry.Value, (int)(range.Key - mergedRootSegment.Key),
          (int)(range.Value - mergedRootSegment.Key)))).ToList();

    var digitalSignatureExData =
      entries.Find(entry => entry.Key.Name.Trim(new[] { '' }).Equals("MsiDigitalSignatureEx")).Value;


    FileMetaInfo = new MsiFileMetaInfo(
      compoundFile.FileSize,
      compoundFile.HeaderMetaInfo,
      entries.Select(entry => entry.Key).ToList(),
      specialEntries,
      specialSegments,
      digitalSignatureExData,
      (int)rootEntry.Key.StartingSectorLocation
    );
  }

  private static HashSet<string> _specialValues = new()
  {
    new string(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 59, 242, 67, 56, 68, 177, 69 })),
    new string(Encoding.Unicode.GetChars(new byte[] { 64, 72, 63, 63, 119, 69, 108, 68, 106, 62, 178, 68, 47, 72 })),
  };

  private static List<KeyValuePair<long, long>> MergeSegments(List<KeyValuePair<long, long>> segments)
  {
    if (segments.Count <= 1) return segments;

    // Sort the segments by Key.
    segments.Sort((x, y) => x.Key.CompareTo(y.Key));

    var result = new List<KeyValuePair<long, long>> { segments[0] };

    for (var i = 1; i < segments.Count; i++)
    {
      // If current segment's start (Key) is less than or equal to previous segment's end (Value), then update previous segment's end (Value)
      if (result.Last().Value >= segments[i].Key)
      {
        var lastElement = result.Last();
        result.Remove(lastElement);
        result.Add(new KeyValuePair<long, long>(lastElement.Key, Math.Max(lastElement.Value, segments[i].Value)));
      }
      else
      {
        result.Add(segments[i]); // Otherwise, add current segment as separate.
      }
    }

    return result;
  }

  internal static List<KeyValuePair<long, long>> FindGaps(long start, long end, List<KeyValuePair<long, long>> segments)
  {
    var gaps = new List<KeyValuePair<long, long>>();
    long currStart = start;

    foreach (var segment in segments)
    {
      long segStart = segment.Key;
      long segEnd = segment.Value;

      if (segStart > currStart)
      {
        gaps.Add(new KeyValuePair<long, long>(currStart - 1, segStart));
      }

      currStart = Math.Max(segEnd, currStart);
    }

    if (currStart <= end)
    {
      gaps.Add(new KeyValuePair<long, long>(currStart, end));
    }

    return gaps;
  }

  internal static byte[] SliceArray(byte[] source, int fromIndex, int toIndex)
  {
    int size = toIndex - fromIndex;
    var result = new byte[size];
    for (int i = 0; i < size; i++)
    {
      result[i] = source[fromIndex + i];
    }

    return result;
  }
}