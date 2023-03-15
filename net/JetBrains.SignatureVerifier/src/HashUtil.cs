using System.IO;
using System.Security.Cryptography;
using JetBrains.FormatRipper;

namespace JetBrains.SignatureVerifier
{
  public static class HashUtil
  {
    public static byte[] ComputeHash(Stream stream, ComputeHashInfo computeHashInfo, HashAlgorithmName hashAlgorithmName)
    {
      using var hash = IncrementalHash.CreateHash(hashAlgorithmName);
      computeHashInfo.WalkOnHashRanges(stream, hash.AppendData);
      return hash.GetHashAndReset();
    }
  }
}