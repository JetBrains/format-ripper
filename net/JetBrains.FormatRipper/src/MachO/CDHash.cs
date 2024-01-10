namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Class that contains hash function name and ComputeHashInfo to calculate a hash of a Mach-o's CodeDirectory structure
/// </summary>
public class CDHash
{
  /// <summary>
  /// Hash function name
  /// </summary>
  public string HashName { get; private set; }

  /// <summary>
  /// Hash calculation range
  /// </summary>
  public ComputeHashInfo ComputeHashInfo { get; private set; }

  internal CDHash(string hashName, ComputeHashInfo computeHashInfo)
  {
    HashName = hashName;
    ComputeHashInfo = computeHashInfo;
  }
}