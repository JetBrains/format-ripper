using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace JetBrains.SignatureVerifier
{
  public static class HashUtil
  {
    public static byte[] ComputeHash(Stream stream, ComputeHashInfo computeHashInfo, string algorithmName)
      => ComputeHash(stream, computeHashInfo, DigestUtilities.GetDigest(algorithmName));

    public static byte[] ComputeHash(Stream stream, ComputeHashInfo computeHashInfo, AlgorithmIdentifier algorithmIdentifier)
      => ComputeHash(stream, computeHashInfo, DigestUtilities.GetDigest(algorithmIdentifier.Algorithm));

    public static byte[] ComputeHash(Stream stream, ComputeHashInfo computeHashInfo, IDigest digest)
    {
      computeHashInfo.WalkOnHashRanges(stream, digest.BlockUpdate);

      byte[] hash = new byte[digest.GetDigestSize()];
      digest.DoFinal(hash, 0);

      return hash;
    }

    public static IDictionary<AlgorithmIdentifier, byte[]> ComputeHashes(Stream stream, ComputeHashInfo computeHashInfo, IEnumerable<string> algorithmNames)
      => ComputeHashes(stream, computeHashInfo, algorithmNames.Select(alg => new AlgorithmIdentifier(DigestUtilities.GetObjectIdentifier(alg))));

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