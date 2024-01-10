using System.Collections.Generic;

namespace JetBrains.FormatRipper.MachO;

/// <summary>
/// Class that contains hash function name, hash calculation ranges and expected hash value
/// </summary>
public class HashVerificationUnit
{
  /// <summary>
  /// Hash function name
  /// </summary>
  public string HashName { get; private set; }

  /// <summary>
  /// Expected value
  /// </summary>
  /// <remarks>Mach-o format may contain truncated hash value for compatibility reason. For example, first 20 bytes of SHA256.</remarks>
  public byte[] ExpectedHashValue { get; private set; }

  /// <summary>
  /// Hash calculation ranges
  /// </summary>
  public ComputeHashInfo ComputeHashInfo { get; private set; }

  internal HashVerificationUnit(string hashName, byte[] expectedHashValue, ComputeHashInfo computeHashInfo)
  {
    HashName = hashName;
    ComputeHashInfo = computeHashInfo;
    ExpectedHashValue = expectedHashValue;
  }
}