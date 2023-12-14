using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using JetBrains.FormatRipper;
using JetBrains.SignatureVerifier.Crypt.BC;
using JetBrains.SignatureVerifier.Crypt.BC.Authenticode;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace JetBrains.SignatureVerifier.Crypt;

/// <summary>
/// Class for file hash validation
/// </summary>
public class FileIntegrityVerifier
{
  [NotNull] private readonly SignedMessage _signedMessage;

  /// <summary>
  /// Constructs new verifier
  /// </summary>
  /// <param name="signedMessage">Files signature</param>
  public FileIntegrityVerifier([NotNull] SignedMessage signedMessage)
  {
    _signedMessage = signedMessage;
  }

  /// <summary>
  /// Calculate file's hash and compare it with value from signature
  /// </summary>
  /// <param name="stream">File stream</param>
  /// <param name="computeHashInfo">Hash computation information</param>
  /// <param name="verificationParams">Verification parameters</param>
  /// <returns>Validation result.
  /// Returns FileIntegrityDataNotFound if the signature token with the expected hash value was not found.</returns>
  public VerifySignatureResult VerifyFileIntegrityAsync(Stream stream, ComputeHashInfo computeHashInfo, FileIntegrityVerificationParams verificationParams)
  {
    var signedDataTokens = GetIndirectDataTokens();

    bool hasValidSignatures = false;
    bool hasInvalidSignatures = false;

    var algorithms = signedDataTokens
      .Select(t => t.IndirectDataContent.DigestInfo.AlgorithmID);

    Dictionary<AlgorithmIdentifier, byte[]> hashes = BcHashUtil.ComputeHashes(stream, computeHashInfo, algorithms);

    foreach (var spcIndirectDataToken in signedDataTokens)
    {
      AlgorithmIdentifier algId = spcIndirectDataToken.IndirectDataContent.DigestInfo.AlgorithmID;

      var imageHash = hashes[algId];

      byte[] expectedHash = spcIndirectDataToken.IndirectDataContent.DigestInfo.GetDigest();

      if (imageHash.Length == expectedHash.Length && Arrays.FixedTimeEquals(imageHash, expectedHash))
      {
        hasValidSignatures = true;
      }
      else
      {
        hasInvalidSignatures = true;
        if (!verificationParams.AllowHashMismatches)
          break;
      }
    }

    VerifySignatureResult result = (hasValidSignatures, hasInvalidSignatures, verificationParams.AllowHashMismatches) switch
    {
      (false, false, _) => new VerifySignatureResult(VerifySignatureStatus.FileIntegrityDataNotFound),
      (true, _, true) => VerifySignatureResult.Valid,
      (true, false, _) => VerifySignatureResult.Valid,
      _ => new VerifySignatureResult(VerifySignatureStatus.InvalidFileHash),
    };

    return result;
  }

  /// <summary>
  /// Extract SPC_INDIRECT_DATA tokens from SignedData's content and from nested signatures
  /// stored in unsigned attributes collection.
  /// </summary>
  /// <returns>List of SPC_INDIRECT_DATA tokens</returns>
  private IEnumerable<SpcIndirectDataToken> GetIndirectDataTokens()
  {
    List<SpcIndirectDataToken> tokens = new List<SpcIndirectDataToken>();

    if (_signedMessage.SignedData.SignedContent != null && _signedMessage.SignedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
    {
      tokens.Add(new SpcIndirectDataToken(_signedMessage.SignedData));
    }

    var signersStore = _signedMessage.SignedData.GetSignerInfos();

    foreach (SignerInformation signer in signersStore.GetSigners())
    {
      if (signer.UnsignedAttributes != null)
      {
        var nestedSignatures = signer.UnsignedAttributes.GetAll(OIDs.SPC_NESTED_SIGNATURE);

        foreach (Attribute nestedSignature in nestedSignatures)
        {
          foreach (var nestedSignatureAttrValue in nestedSignature.AttrValues)
          {
            var contentInfo = ContentInfo.GetInstance(nestedSignatureAttrValue);
            var cmsSignedData = new CmsSignedData(contentInfo);

            if (cmsSignedData.SignedContent != null && cmsSignedData.SignedContentType.Equals(OIDs.SPC_INDIRECT_DATA))
            {
              tokens.Add(new SpcIndirectDataToken(cmsSignedData));
            }
          }
        }
      }
    }

    return tokens;
  }
}