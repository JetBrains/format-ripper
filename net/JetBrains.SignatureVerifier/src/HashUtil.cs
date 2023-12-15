using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using JetBrains.FormatRipper;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

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

    public static IDictionary<HashAlgorithmName, byte[]> ComputeHashes(Stream stream, ComputeHashInfo computeHashInfo, IEnumerable<HashAlgorithmName> hashAlgorithmNames)
    {
      Dictionary<HashAlgorithmName, IncrementalHash> algorithms = new Dictionary<HashAlgorithmName, IncrementalHash>();
      Dictionary<HashAlgorithmName, byte[]> hashes = new Dictionary<HashAlgorithmName, byte[]>();

      try
      {
        foreach (var algorithmIdentifier in hashAlgorithmNames)
        {
          if (!algorithms.ContainsKey(algorithmIdentifier))
            algorithms.Add(algorithmIdentifier, IncrementalHash.CreateHash(algorithmIdentifier));
        }

        // Read from the stream and update the digest
        computeHashInfo.WalkOnHashRanges(stream, (buffer, index, count) =>
        {
          foreach (var digest in algorithms.Values)
            digest.AppendData(buffer, index, count);
        });

        // Finalize hashes calculation
        foreach (var algorithm in algorithms)
        {
          byte[] hash = algorithm.Value.GetHashAndReset();
          hashes.Add(algorithm.Key, hash);
        }
      }
      finally
      {
        foreach (var algorithm in algorithms.Values)
          algorithm.Dispose();
      }

      return hashes;
    }

    public static byte[] ComputeHash(Stream stream, ComputeHashInfo computeHashInfo, AlgorithmIdentifier algorithmIdentifier)
    {
      IDigest digest = DigestUtilities.GetDigest(algorithmIdentifier.Algorithm);
      computeHashInfo.WalkOnHashRanges(stream, digest.BlockUpdate);

      byte[] hash = new byte[digest.GetDigestSize()];
      digest.DoFinal(hash, 0);

      return hash;
    }

    public static IDictionary<AlgorithmIdentifier, byte[]> ComputeHashes(Stream stream, ComputeHashInfo computeHashInfo, IEnumerable<AlgorithmIdentifier> algorithmIdentifiers)
    {
      Dictionary<AlgorithmIdentifier, IDigest> algorithms = new Dictionary<AlgorithmIdentifier, IDigest>();

      foreach (var algorithmIdentifier in algorithmIdentifiers)
      {
        if (!algorithms.ContainsKey(algorithmIdentifier))
        {
          IDigest digest = DigestUtilities.GetDigest(algorithmIdentifier.Algorithm);
          algorithms.Add(algorithmIdentifier, digest);
        }
      }

      // Read from the stream and update the digest
      computeHashInfo.WalkOnHashRanges(stream, (buffer, index, count) =>
      {
        foreach (var digest in algorithms.Values)
          digest.BlockUpdate(buffer, index, count);
      });

      Dictionary<AlgorithmIdentifier, byte[]> hashes = new Dictionary<AlgorithmIdentifier, byte[]>();

      // Finalize hashes calculation
      foreach (var algorithm in algorithms)
      {
        byte[] hash = new byte[algorithm.Value.GetDigestSize()];
        algorithm.Value.DoFinal(hash, 0);
        hashes.Add(algorithm.Key, hash);
      }

      return hashes;
    }
  }
}