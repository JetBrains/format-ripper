using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.FormatRipper;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace JetBrains.SignatureVerifier;

public static class BcHashUtil
{
  public static Dictionary<AlgorithmIdentifier, byte[]> ComputeHashes(Stream stream, ComputeHashInfo computeHashInfo, IEnumerable<AlgorithmIdentifier> algorithmIdentifiers)
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

    // Finalize the hash calculation
    foreach (var algorithm in algorithms)
    {
      byte[] hash = new byte[algorithm.Value.GetDigestSize()];
      algorithm.Value.DoFinal(hash, 0);
      hashes.Add(algorithm.Key, hash);
    }

    return hashes;
  }
}