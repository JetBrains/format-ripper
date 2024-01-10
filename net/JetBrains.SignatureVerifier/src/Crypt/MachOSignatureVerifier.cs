using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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

/// <summary>
/// Mach-o format signatures verifier
/// </summary>
public class MachOSignatureVerifier
{
  [CanBeNull] private readonly ILogger _logger;

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="logger">Logger</param>
  public MachOSignatureVerifier([CanBeNull] ILogger logger)
  {
    _logger = logger;
  }

  /// <summary>
  /// Verify digital signature and file integrity of a Mach-o file
  /// </summary>
  /// <param name="machOFile">Parsed Mach-o file</param>
  /// <param name="stream">Mach-o file raw stream</param>
  /// <param name="signatureVerificationParams">Verification params</param>
  /// <returns>Verification result</returns>
  public async Task<VerifySignatureResult> VerifyAsync(MachOFile machOFile, Stream stream, SignatureVerificationParams signatureVerificationParams)
  {
    foreach (var section in machOFile.Sections)
    {
      var sectionVerificationResult = await VerifyAsync(section, stream, signatureVerificationParams);

      if (!sectionVerificationResult.IsValid)
        return sectionVerificationResult;
    }

    return VerifySignatureResult.Valid;
  }

  /// <summary>
  /// Verify digital signature and file integrity of a single Mach-o file section
  /// </summary>
  /// <param name="section">Mach-o file section</param>
  /// <param name="stream">Mach-o file raw stream. A stream of the entire file is expected.</param>
  /// <param name="signatureVerificationParams">Verification params</param>
  /// <returns>Verification result</returns>
  public async Task<VerifySignatureResult> VerifyAsync(MachOFile.Section section, Stream stream, SignatureVerificationParams signatureVerificationParams)
  {
    var signedMessage = SignedMessage.CreateInstance(section.SignatureData);
    var signedMessageVerifier = new SignedMessageVerifier(_logger);
    var signatureVerificationResult = await signedMessageVerifier.VerifySignatureAsync(signedMessage, signatureVerificationParams);

    if (!signatureVerificationResult.IsValid)
      return signatureVerificationResult;

    var codeDirectoryValidationResult = VerifyCodeDirectories(stream, section);

    if (!codeDirectoryValidationResult.IsValid)
      return codeDirectoryValidationResult;

    if (!section.CDHashes.Any())
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);

    if (section.CDHashes.Count() > 1)
    {
      var cdHashesVerificationResult = VerifyCDHashes(stream, section.CDHashes, signedMessage);

      if (!cdHashesVerificationResult.IsValid)
        return cdHashesVerificationResult;
    }

    return VerifySignatureResult.Valid;
  }

  private static VerifySignatureResult VerifyCodeDirectories(Stream stream, MachOFile.Section section)
  {
    if (!section.HashVerificationUnits.Any())
      return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);

    foreach (var hashVerificationUnit in section.HashVerificationUnits)
    {
      var hash = HashUtil.ComputeHash(stream, hashVerificationUnit.ComputeHashInfo, hashVerificationUnit.HashName);

      bool equals = Arrays.FixedTimeEquals(hashVerificationUnit.ExpectedHashValue, hash.Take(hashVerificationUnit.ExpectedHashValue.Length).ToArray());

      if (!equals)
        return new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash);
    }

    return VerifySignatureResult.Valid;
  }

  private VerifySignatureResult VerifyCDHashes(Stream stream, IEnumerable<CDHash> cdHashesInfo, SignedMessage sectionSignature)
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

  private IEnumerable<DigestInfo> GetHashAgilityV2Hashes(SignedMessage signedMessage)
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

  private IEnumerable<byte[]> GetHashAgilityV1Hashes(SignedMessage signedMessage)
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