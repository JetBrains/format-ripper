using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using JetBrains.Annotations;
using JetBrains.FormatRipper.MachO;
using JetBrains.SignatureVerifier.Crypt.BC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.SignatureVerifier.Crypt;

public class AppleSignatureVerifier
{
  protected readonly ILogger _logger;
  protected readonly SignedMessageVerifier _signedMessageVerifier;

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="logger">Logger</param>
  public AppleSignatureVerifier([CanBeNull] ILogger logger) : this(new SignedMessageVerifier(logger), logger)
  {
  }

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="signedMessageVerifier">Signed message verifier</param>
  /// <param name="logger">Logger</param>
  public AppleSignatureVerifier([NotNull] SignedMessageVerifier signedMessageVerifier, [CanBeNull] ILogger logger)
  {
    _signedMessageVerifier = signedMessageVerifier ?? throw new ArgumentNullException(nameof(signedMessageVerifier));
    _logger = logger ?? NullLogger.Instance;
  }

  /// <summary>
  /// Compute hash value of provided hash verification units and validate against expected value
  /// </summary>
  /// <param name="stream">File stream</param>
  /// <param name="hashVerificationUnits">List of hash verification units</param>
  /// <returns>Hash units verification result</returns>
  public static VerifySignatureResult VerifyHashVerificationUnits(Stream stream, IEnumerable<HashVerificationUnit> hashVerificationUnits)
  {
    foreach (var hashVerificationUnit in hashVerificationUnits)
    {
      var hash = HashUtil.ComputeHash(stream, hashVerificationUnit.ComputeHashInfo, hashVerificationUnit.HashName);

      int length = Math.Min(hashVerificationUnit.ExpectedHashValue.Length, hash.Length);
      bool equals = Arrays.FixedTimeEquals(length, hashVerificationUnit.ExpectedHashValue, 0, hash, 0);

      if (!equals)
        return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    return VerifySignatureResult.Valid;
  }

  /// <summary>
  /// Verify Code Directories integrity
  /// </summary>
  /// <param name="stream">Mach-o file stream</param>
  /// <param name="cdHashesInfo">Code Directories hash calculation info</param>
  /// <param name="sectionSignature">Signed message</param>
  /// <returns>Code Directories integrity verification result</returns>
  public VerifySignatureResult VerifyCDHashes(Stream stream, IEnumerable<CDHash> cdHashesInfo, SignedMessage sectionSignature)
  {
    Dictionary<AlgorithmIdentifier, byte[]> hashesToVerify = new Dictionary<AlgorithmIdentifier, byte[]>();

    foreach (var cdHash in cdHashesInfo)
    {
      var hashId = new AlgorithmIdentifier(DigestUtilities.GetObjectIdentifier(cdHash.HashName));
      var hashValue = HashUtil.ComputeHash(stream, cdHash.ComputeHashInfo, hashId);

      hashesToVerify.Add(hashId, hashValue);
    }

    // Checking APPLE_HASH_AGILITY_V2 attribute for CDHash values
    var expectedCdHashValues = GetHashAgilityV2Hashes(sectionSignature);

    foreach (var cdHashValue in expectedCdHashValues)
    {
      AlgorithmIdentifier algId = cdHashValue.AlgorithmID;

      if (hashesToVerify.ContainsKey(algId))
      {
        var hashValue = hashesToVerify[algId];
        var expectedDigest = cdHashValue.GetDigest();

        int length = Math.Min(expectedDigest.Length, hashValue.Length);

        bool equals = Arrays.FixedTimeEquals( length, expectedDigest, 0, hashValue, 0);

        if (equals)
          hashesToVerify.Remove(algId);
        else
          return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
      }
    }

    if (hashesToVerify.Count == 0)
      return VerifySignatureResult.Valid;

    // Fallback for older APPLE_HASH_AGILITY attribute
    var expectedHashValues = GetHashAgilityV1Hashes(sectionSignature);

    foreach (var expectedHashValue in expectedHashValues)
    {
      AlgorithmIdentifier foundKey = null;

      foreach (var hashToVerifyKeyPair in hashesToVerify)
      {
        int length = Math.Min(expectedHashValue.Length, hashToVerifyKeyPair.Value.Length);

        if (Arrays.FixedTimeEquals(length, expectedHashValue, 0, hashToVerifyKeyPair.Value, 0))
        {
          foundKey = hashToVerifyKeyPair.Key;
          break;
        }
      }

      if (foundKey != null)
        hashesToVerify.Remove(foundKey);
    }

    return hashesToVerify.Count == 0 ? VerifySignatureResult.Valid : new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
  }

  /// <summary>
  /// Get expected CDHash values from APPLE_HASH_AGILITY_V2 (1.2.840.113635.100.9.2) attribute
  /// </summary>
  /// <param name="signedMessage">Signed message</param>
  /// <returns>List of DigestInfos which contains hash function oid and expected value</returns>
  public IEnumerable<DigestInfo> GetHashAgilityV2Hashes(SignedMessage signedMessage)
  {
    List<DigestInfo> tokens = new List<DigestInfo>();

    var signersStore = signedMessage.SignedData.GetSignerInfos();

    foreach (SignerInformation signer in signersStore.GetSigners())
    {
      if (signer.SignedAttributes != null)
      {
        var appleHashAgilitiesV2 = signer.SignedAttributes.GetAll(OIDs.APPLE_HASH_AGILITY_V2);

        foreach (Attribute appleHashAgility in appleHashAgilitiesV2)
        {
          foreach (var appleHashAgilityValue in appleHashAgility.AttrValues)
          {
            var seq = (Asn1Sequence)appleHashAgilityValue;

            if (seq.Count == 2 && seq[0] is DerObjectIdentifier)
            {
              var algorithmIdentifier = new AlgorithmIdentifier((DerObjectIdentifier)seq[0]);
              var digest = Asn1OctetString.GetInstance(seq[1]).GetOctets();
              var contentInfo = new DigestInfo(algorithmIdentifier, digest);

              tokens.Add(contentInfo);
            }
          }
        }
      }
    }

    return tokens;
  }

  /// <summary>
  /// Get expected CDHash values from APPLE_HASH_AGILITY (1.2.840.113635.100.9.1) attribute
  /// </summary>
  /// <param name="signedMessage">Signed message</param>
  /// <returns>List of expected hash values (without hash algorithm id)</returns>
  public IEnumerable<byte[]> GetHashAgilityV1Hashes(SignedMessage signedMessage)
  {
    List<byte[]> hashesList = new List<byte[]>();

    var signersStore = signedMessage.SignedData.GetSignerInfos();

    foreach (SignerInformation signer in signersStore.GetSigners())
    {
      var appleHashAgilities = signer.SignedAttributes.GetAll(OIDs.APPLE_HASH_AGILITY);

      foreach (Attribute appleHashAgility in appleHashAgilities)
      {
        foreach (var nestedSignatureAttrValue in appleHashAgility.AttrValues)
        {
          if (nestedSignatureAttrValue is DerOctetString seq)
          {
            try
            {
              var hashesXml = Encoding.UTF8.GetString(seq.GetOctets());
              XDocument plist = XDocument.Parse(hashesXml);
              IEnumerable<byte[]> dataValues = plist.Descendants("data")
                .Select(x => Convert.FromBase64String((string)x));

              hashesList.AddRange(dataValues);
            }
            catch (Exception e)
            {
              _logger?.Warning($"Error parsing APPLE_HASH_AGILITY attribute value: {e.Message}");
            }
          }
        }
      }
    }

    return hashesList;
  }
}